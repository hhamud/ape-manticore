"""Symbolic EVM implementation based on the yellow paper: http://gavwood.com/paper.pdf"""
import uuid
import binascii
import random
import io
import copy
import inspect
from functools import wraps
from typing import List, Set, Tuple, Union
from ...platforms.platform import *
from ...core.smtlib import (
    SelectedSolver,
    BitVec,
    Array,
    ArrayProxy,
    Operators,
    Constant,
    ArrayVariable,
    ArrayStore,
    BitVecConstant,
    translate_to_smtlib,
    to_constant,
    simplify,
    get_depth,
    issymbolic,
    get_taints,
    istainted,
    taint_with,
)
from ...core.state import Concretize, TerminateState
from ...utils.event import Eventful
from ...utils.helpers import printable_bytes
from ...core.smtlib.visitors import simplify
from ...exceptions import EthereumError
import pyevmasm as EVMAsm
import logging
from collections import namedtuple
import sha3
import rlp
from .common import *
from .exceptions import *


logger = logging.getLogger(__name__)

# Gas behaviour configuration
# When gas is concrete the gas checks and calculation are pretty straight forward
# Though Gas can became symbolic in normal bytecode execution for example at instructions
# MSTORE, MSTORE8, EXP, ... and every instruction with internal operation restricted by gas
# This configuration variable allows the user to control and perhaps relax the gas calculation
#
# This configuration variable allows the user to control and perhaps relax the gas calculation
# pedantic: gas is faithfully accounted and checked at instruction level. State may get forked in OOG/NoOOG
# complete: gas is faithfully accounted and checked at basic blocks limits. State may get forked in OOG/NoOOG
# concrete: concretize gas: if the fee to be consumed gets to be symbolic choose some potential values and fork on those
# optimistic: Try not to OOG. If it may be enough gas we ignore the OOG case. A constraint is added to assert the gas is enough and the OOG state is ignored.
# pesimistic: OOG soon. If it may NOT be enough gas we ignore the normal case. A constraint is added to assert the gas is NOT enough and the other state is ignored.
# ignore: Ignore gas. Do not account for it. Do not OOG.
class EVM(Eventful):
    """
    Machine State. The machine state is defined as
    the tuple (g, pc, m, i, s) which are the gas available, the
    program counter pc , the memory contents, the active
    number of words in memory (counting continuously
    from position 0), and the stack contents. The memory
    contents are a series of zeroes of bitsize 256
    """

    _published_events = {
        "evm_execute_instruction",
        "evm_read_storage",
        "evm_write_storage",
        "evm_read_memory",
        "evm_write_memory",
        "evm_read_code",
        "evm_write_code",
        "decode_instruction",
        "on_unsound_symbolication",
        "solve",
    }

    class transact:
        def __init__(self, pre=None, pos=None, doc=None):
            self._pre = pre
            self._pos = pos
            if doc is None and pre is not None:
                doc = pre.__doc__
            self.__doc__ = doc
            self.__name__ = pre.__name__

        def __get__(self, obj, objtype=None):
            if obj is None:
                return self
            if self._pre is None:
                raise AttributeError("unreadable attribute")
            from types import MethodType

            @wraps(self._pre)
            def _pre_func(my_obj, *args, **kwargs):
                if my_obj._on_transaction:
                    result = self._pos(my_obj, *args, **kwargs)
                    my_obj._on_transaction = False
                    return result
                else:
                    try:
                        self._pre(my_obj, *args, **kwargs)
                        raise AssertionError(
                            "The pre-transaction handler must raise a StartTx transaction"
                        )
                    except StartTx:
                        my_obj._on_transaction = True
                        raise

            return MethodType(_pre_func, obj)

        def __set__(self, obj, value):
            raise AttributeError("can't set attribute")

        def __delete__(self, obj):
            raise AttributeError("can't delete attribute")

        def pos(self, pos):
            return type(self)(self._pre, pos)

    def __init__(
        self,
        constraints,
        address,
        data,
        caller,
        value,
        bytecode,
        world=None,
        gas=None,
        fork=DEFAULT_FORK,
        **kwargs,
    ):
        """
        Builds a Ethereum Virtual Machine instance

        :param memory: the initial memory
        :param address: the address of the account which owns the code that is executing.
        :param data: the byte array that is the input data to this execution
        :param caller: the address of the account which caused the code to be executing. A 160-bit code used for identifying Accounts
        :param value: the value, in Wei, passed to this account as part of the same procedure as execution. One Ether is defined as being 10**18 Wei
        :param bytecode: the byte array that is the machine code to be executed
        :param world: the EVMWorld object where the transaction is being executed
        :param gas: gas budget for this transaction
        """
        super().__init__(**kwargs)
        if data is not None and not issymbolic(data):
            data_size = len(data)
            data_symbolic = constraints.new_array(
                index_bits=256,
                value_bits=8,
                index_max=data_size,
                name=f"DATA_{address:x}",
                avoid_collisions=True,
                default=0,
            )
            data_symbolic[0:data_size] = data
            data = data_symbolic

        if bytecode is not None and not issymbolic(bytecode):
            bytecode_size = len(bytecode)
            bytecode_symbolic = constraints.new_array(
                index_bits=256,
                value_bits=8,
                index_max=bytecode_size,
                name=f"BYTECODE_{address:x}",
                avoid_collisions=True,
                default=0,
            )
            bytecode_symbolic[0:bytecode_size] = bytecode
            bytecode = bytecode_symbolic

        # TODO: Handle the case in which bytecode is symbolic (This happens at
        # CREATE instructions that has the arguments appended to the bytecode)
        # This is a very cornered corner case in which code is actually symbolic
        # We should simply not allow to jump to unconstrained(*) symbolic code.
        # (*) bytecode that could take more than a single value
        self._need_check_jumpdest = False
        self._valid_jumpdests = set()

        # Compile the list of valid jumpdests via linear dissassembly
        def extend_with_zeroes(b):
            try:
                for x in b:
                    x = to_constant(x)
                    if isinstance(x, int):
                        yield (x)
                    else:
                        yield (0)
                for _ in range(32):
                    yield (0)
            except Exception as e:
                return

        for i in EVMAsm.disassemble_all(extend_with_zeroes(bytecode)):
            if i.mnemonic == "JUMPDEST":
                self._valid_jumpdests.add(i.pc)

        # A no code VM is used to execute transactions to normal accounts.
        # I'll execute a STOP and close the transaction
        # if len(bytecode) == 0:
        #    raise EVMException("Need code")
        self._constraints = constraints
        # Uninitialized values in memory are 0 by spec
        self.memory = constraints.new_array(
            index_bits=256,
            value_bits=8,
            name=f"EMPTY_MEMORY_{address:x}",
            avoid_collisions=True,
            default=0,
        )
        self.address = address
        self.caller = (
            caller  # address of the account that is directly responsible for this execution
        )
        self.data = data
        self.value = value
        self._bytecode = bytecode
        self.suicides = set()
        self.logs = []
        # FIXME parse decode and mark invalid instructions
        # self.invalid = set()

        # Machine state
        self.evmfork = fork
        self._pc = 0
        self.stack = []
        # We maintain gas as a 512 bits internally to avoid overflows
        # it is shortened to 256 bits when it is used by the GAS instruction
        self._gas = Operators.ZEXTEND(gas, 512)
        self._world = world
        self._allocated = 0
        self._on_transaction = False  # for @transact
        self._checkpoint_data = None
        self._published_pre_instruction_events = False
        self._return_data = b""

        # Used calldata size
        self._used_calldata_size = 0
        self._valid_jmpdests = set()
        self._sha3 = {}
        self._refund = 0
        self._temp_call_gas = None
        self._failed = False

    def fail_if(self, failed):
        self._failed = Operators.OR(self._failed, failed)

    def is_failed(self):
        if isinstance(self._failed, bool):
            return self._failed

        self._failed = simplify(self._failed)
        if isinstance(self._failed, Constant):
            return self._failed.value

        def setstate(state, value):
            state.platform._failed = value

        raise Concretize(
            "Transaction failed", expression=self._failed, setstate=lambda a, b: None, policy="ALL"
        )

    @property
    def pc(self):
        return self._pc

    @pc.setter
    def pc(self, pc):
        self._pc = simplify(pc)

    @property
    def bytecode(self):
        return self._bytecode

    @property
    def constraints(self):
        return self._constraints

    @constraints.setter
    def constraints(self, constraints):
        self._constraints = constraints
        self.memory.constraints = constraints

    @property
    def gas(self):
        return Operators.EXTRACT(self._gas, 0, 256)

    def __getstate__(self):
        state = super().__getstate__()
        state["sha3"] = self._sha3
        state["memory"] = self.memory
        state["world"] = self._world
        state["constraints"] = self.constraints
        state["address"] = self.address
        state["caller"] = self.caller
        state["data"] = self.data
        state["value"] = self.value
        state["bytecode"] = self._bytecode
        state["pc"] = self.pc
        state["stack"] = self.stack
        state["gas"] = self._gas
        state["allocated"] = self._allocated
        state["suicides"] = self.suicides
        state["logs"] = self.logs
        state["_on_transaction"] = self._on_transaction
        state["_checkpoint_data"] = self._checkpoint_data
        state["_published_pre_instruction_events"] = self._published_pre_instruction_events
        state["_used_calldata_size"] = self._used_calldata_size
        state["_valid_jumpdests"] = self._valid_jumpdests
        state["_need_check_jumpdest"] = self._need_check_jumpdest
        state["_return_data"] = self._return_data
        state["evmfork"] = self.evmfork
        state["_refund"] = self._refund
        state["_temp_call_gas"] = self._temp_call_gas
        state["_failed"] = self._failed
        return state

    def __setstate__(self, state):
        self._sha3 = state["sha3"]
        self._checkpoint_data = state["_checkpoint_data"]
        self._published_pre_instruction_events = state["_published_pre_instruction_events"]
        self._on_transaction = state["_on_transaction"]
        self._gas = state["gas"]
        self.memory = state["memory"]
        self.logs = state["logs"]
        self._world = state["world"]
        self.constraints = state["constraints"]
        self.address = state["address"]
        self.caller = state["caller"]
        self.data = state["data"]
        self.value = state["value"]
        self._bytecode = state["bytecode"]
        self.pc = state["pc"]
        self.stack = state["stack"]
        self._allocated = state["allocated"]
        self.suicides = state["suicides"]
        self._used_calldata_size = state["_used_calldata_size"]
        self._valid_jumpdests = state["_valid_jumpdests"]
        self._need_check_jumpdest = state["_need_check_jumpdest"]
        self._return_data = state["_return_data"]
        self.evmfork = state["evmfork"]
        self._refund = state["_refund"]
        self._temp_call_gas = state["_temp_call_gas"]
        self._failed = state["_failed"]
        super().__setstate__(state)

    def _get_memfee(self, address, size=1):
        """
        This calculates the amount of extra gas needed for accessing to
        previously unused memory.

        :param address: base memory offset
        :param size: size of the memory access
        """
        if not issymbolic(size) and size == 0:
            return 0

        address = self.safe_add(address, size)
        allocated = self.allocated
        GMEMORY = 3
        GQUADRATICMEMDENOM = 512  # 1 gas per 512 quadwords
        old_size = Operators.ZEXTEND(Operators.UDIV(self.safe_add(allocated, 31), 32), 512)
        new_size = Operators.ZEXTEND(Operators.UDIV(self.safe_add(address, 31), 32), 512)

        old_totalfee = self.safe_mul(old_size, GMEMORY) + Operators.UDIV(
            self.safe_mul(old_size, old_size), GQUADRATICMEMDENOM
        )
        new_totalfee = self.safe_mul(new_size, GMEMORY) + Operators.UDIV(
            self.safe_mul(new_size, new_size), GQUADRATICMEMDENOM
        )
        memfee = new_totalfee - old_totalfee
        flag = Operators.UGT(new_totalfee, old_totalfee)
        return Operators.ITEBV(512, size == 0, 0, Operators.ITEBV(512, flag, memfee, 0))

    def _allocate(self, address, size=1):
        address_c = Operators.UDIV(self.safe_add(address, size, 31), 32) * 32
        self._allocated = Operators.ITEBV(
            512, Operators.UGT(address_c, self._allocated), address_c, self.allocated
        )

    @property
    def allocated(self):
        return self._allocated

    @property
    def world(self):
        return self._world

    @staticmethod
    def check256int(value):
        assert True

    def read_code(self, address, size=1):
        """
        Read size byte from bytecode.
        If less than size bytes are available result will be pad with \x00
        """
        assert address < len(self.bytecode)
        value = self.bytecode[address : address + size]
        if len(value) < size:
            value += "\x00" * (size - len(value))  # pad with null (spec)
        return value

    def disassemble(self):
        return EVMAsm.disassemble(self.bytecode)

    @property
    def PC(self):
        return self.pc

    def _getcode(self, pc):
        bytecode = self.bytecode
        for pc_i in range(pc, len(bytecode)):
            yield simplify(bytecode[pc_i]).value
        while True:
            yield 0  # STOP opcode

    @property
    def instruction(self):
        """
        Current instruction pointed by self.pc
        """
        # FIXME check if pc points to invalid instruction
        # if self.pc >= len(self.bytecode):
        #    return InvalidOpcode('Code out of range')
        # if self.pc in self.invalid:
        #    raise InvalidOpcode('Opcode inside a PUSH immediate')
        try:
            _decoding_cache = getattr(self, "_decoding_cache")
        except Exception:
            self._decoding_cache = {}
            _decoding_cache = self._decoding_cache

        pc = self.pc
        if isinstance(pc, Constant):
            pc = pc.value

        if pc in _decoding_cache:
            return _decoding_cache[pc]

        instruction = EVMAsm.disassemble_one(self._getcode(pc), pc=pc, fork=self.evmfork)
        _decoding_cache[pc] = instruction
        return instruction

    # auxiliary funcs
    def _throw(self):
        self._gas = 0
        raise InvalidOpcode()

    # Stack related
    def _push(self, value):
        """
        Push into the stack

              ITEM0
              ITEM1
              ITEM2
        sp->  {empty}
        """
        assert isinstance(value, int) or isinstance(value, BitVec) and value.size == 256
        if len(self.stack) >= 1024:
            raise StackOverflow()

        if isinstance(value, int):
            value = value & TT256M1

        value = simplify(value)
        if isinstance(value, Constant) and not value.taint:
            value = value.value

        self.stack.append(value)

    def _top(self, n=0):
        """Read a value from the top of the stack without removing it"""
        if len(self.stack) - n < 0:
            raise StackUnderflow()
        return self.stack[n - 1]

    def _pop(self):
        """Pop a value from the stack"""
        if not self.stack:
            raise StackUnderflow()
        return self.stack.pop()

    def _consume(self, fee):
        # Check type and bitvec size
        if isinstance(fee, int):
            if fee > (1 << 512) - 1:
                raise ValueError
        elif isinstance(fee, BitVec):
            if fee.size != 512:
                raise ValueError("Fees should be 512 bit long")
        # This configuration variable allows the user to control and perhaps relax the gas calculation
        # pedantic: gas is faithfully accounted and checked at instruction level. State may get forked in OOG/NoOOG
        # complete: gas is faithfully accounted and checked at basic blocks limits. State may get forked in OOG/NoOOG
        # concrete: Concretize gas. If the fee to be consumed gets to be symbolic. Choose some potential values and fork on those.
        # optimistic: Try not to OOG. If it may be enough gas we ignore the OOG case. A constraint is added to assert the gas is enough and the OOG state is ignored.
        # pesimistic: OOG soon. If it may NOT be enough gas we ignore the normal case. A constraint is added to assert the gas is NOT enough and the other state is ignored.
        # ignore: Ignore gas. Do not account for it. Do not OOG.

        oog_condition = simplify(Operators.ULT(self._gas, fee))
        self.fail_if(oog_condition)

        self._gas = simplify(self._gas - fee)
        if isinstance(self._gas, Constant) and not self._gas.taint:
            self._gas = self._gas.value

    def check_oog(self):
        if consts.oog == "concrete":
            # Keep gas concrete and ogg checked at every instruction
            if issymbolic(self._gas):
                raise ConcretizeGas()
            if self.is_failed():
                raise NotEnoughGas()

        if consts.oog == "pedantic":
            # gas is faithfully accounted and ogg checked at every instruction
            if self.is_failed():
                raise NotEnoughGas()

        elif consts.oog == "complete":
            if self.instruction.is_terminator:
                # gas is faithfully accounted and ogg checked at every BB
                if self.is_failed():
                    raise NotEnoughGas()

        elif consts.oog == "optimistic":
            self.constraints.add(self._failed == False)
            if self.is_failed():
                raise NotEnoughGas()

        elif consts.oog == "pessimistic":
            # OOG soon. If it may NOT be enough gas we ignore the normal case.
            # A constraint is added to assert the gas is NOT enough and the other state is ignored.
            # explore only when there is enough gas if possible
            self.constraints.add(self._failed == True)
            if self.is_failed():
                raise NotEnoughGas()
        else:
            assert consts.oog == "ignore", "Wrong oog config variable"
            # do nothing. gas is not even changed
            return

        # If everything is concrete lets just check at every instruction
        if not issymbolic(self._gas) and self._gas < 0:
            raise NotEnoughGas()

    def _indemnify(self, fee):
        self._gas += fee

    def _pop_arguments(self):
        # Get arguments (imm, pop)
        current = self.instruction
        arguments = []
        if current.has_operand:
            arguments.append(current.operand)
        for _ in range(current.pops):
            arguments.append(self._pop())
        # simplify stack arguments
        return arguments

    def _top_arguments(self):
        # Get arguments (imm, top). Stack is not changed
        current = self.instruction
        arguments = []
        if current.has_operand:
            arguments.append(current.operand)

        if current.pops:
            arguments.extend(reversed(self.stack[-current.pops :]))
        return arguments

    def _push_arguments(self, arguments):
        # Immediate operands should not be pushed
        start = int(self.instruction.has_operand)
        for arg in reversed(arguments[start:]):
            self._push(arg)

    def _push_results(self, instruction, result):
        # Check result (push)
        if instruction.pushes > 1:
            assert len(result) == instruction.pushes
            for value in reversed(result):
                self._push(value)
        elif instruction.pushes == 1:
            self._push(result)
        else:
            assert instruction.pushes == 0
            assert result is None

    def _calculate_gas(self, *arguments):
        current = self.instruction
        implementation = getattr(self, f"{current.semantics}_gas", None)
        if implementation is None:
            return current.fee
        return current.fee + implementation(*arguments)

    def _handler(self, *arguments):
        current = self.instruction
        implementation = getattr(self, current.semantics, None)
        if implementation is None:
            raise TerminateState(f"Instruction not implemented {current.semantics}", testcase=True)
        return implementation(*arguments)

    def _checkpoint(self):
        """Save and/or get a state checkpoint previous to current instruction"""
        # Fixme[felipe] add a with self.disabled_events context manager to Eventful
        if self._checkpoint_data is None:
            if not self._published_pre_instruction_events:
                self._published_pre_instruction_events = True
                # self._publish("will_decode_instruction", self.pc)
                self._publish(
                    "will_evm_execute_instruction", self.instruction, self._top_arguments()
                )

            pc = self.pc
            instruction = self.instruction
            old_gas = self.gas
            allocated = self._allocated
            # FIXME Not clear which exception should trigger first. OOG or insufficient stack
            # this could raise an insufficient stack exception
            arguments = self._pop_arguments()
            fee = self._calculate_gas(*arguments)

            self._checkpoint_data = (pc, old_gas, instruction, arguments, fee, allocated)
            self._consume(fee)
            self.check_oog()

        return self._checkpoint_data

    def _rollback(self):
        """Revert the stack, gas, pc and memory allocation so it looks like before executing the instruction"""
        last_pc, last_gas, last_instruction, last_arguments, fee, allocated = self._checkpoint_data
        self._push_arguments(last_arguments)
        self._gas = last_gas
        self.pc = last_pc
        self._allocated = allocated
        self._checkpoint_data = None

    def _set_check_jmpdest(self, flag=True):
        """
        Next instruction must be a JUMPDEST iff `flag` holds.

        Note that at this point `flag` can be the conditional from a JUMPI
        instruction hence potentially a symbolic value.
        """
        self._need_check_jumpdest = flag

    def _check_jmpdest(self):
        """
        If the previous instruction was a JUMP/JUMPI and the conditional was
        True, this checks that the current instruction must be a JUMPDEST.

        Here, if symbolic, the conditional `self._need_check_jumpdest` would be
        already constrained to a single concrete value.
        """
        # If pc is already pointing to a JUMPDEST thre is no need to check.
        pc = self.pc.value if isinstance(self.pc, Constant) else self.pc
        if pc in self._valid_jumpdests:
            self._need_check_jumpdest = False
            return

        should_check_jumpdest = simplify(self._need_check_jumpdest)
        if isinstance(should_check_jumpdest, Constant):
            should_check_jumpdest = should_check_jumpdest.value
        elif issymbolic(should_check_jumpdest):
            self._publish("will_solve", self.constraints, should_check_jumpdest, "get_all_values")
            should_check_jumpdest_solutions = SelectedSolver.instance().get_all_values(
                self.constraints, should_check_jumpdest
            )
            self._publish(
                "did_solve",
                self.constraints,
                should_check_jumpdest,
                "get_all_values",
                should_check_jumpdest_solutions,
            )
            if len(should_check_jumpdest_solutions) != 1:
                raise EthereumError("Conditional not concretized at JMPDEST check")
            should_check_jumpdest = should_check_jumpdest_solutions[0]

        # If it can be solved only to False just set it False. If it can be solved
        # only to True, process it and also set it to False
        self._need_check_jumpdest = False

        if should_check_jumpdest:
            if pc not in self._valid_jumpdests:
                self._throw()

    def _advance(self, result=None, exception=False):
        if self._checkpoint_data is None:
            return
        last_pc, last_gas, last_instruction, last_arguments, fee, allocated = self._checkpoint_data
        if not exception:
            if not last_instruction.is_branch:
                # advance pc pointer
                self.pc += last_instruction.size
            self._push_results(last_instruction, result)
        self._publish("did_evm_execute_instruction", last_instruction, last_arguments, result)
        self._checkpoint_data = None
        self._published_pre_instruction_events = False

    def change_last_result(self, result):
        last_pc, last_gas, last_instruction, last_arguments, fee, allocated = self._checkpoint_data

        # Check result (push)\
        if last_instruction.pushes > 1:
            assert len(result) == last_instruction.pushes
            for _ in range(last_instruction.pushes):
                self._pop()
            for value in reversed(result):
                self._push(value)
        elif last_instruction.pushes == 1:
            self._pop()
            self._push(result)
        else:
            assert last_instruction.pushes == 0
            assert result is None

    # Execute an instruction from current pc
    def execute(self):
        pc = self.pc
        if issymbolic(pc) and not isinstance(pc, Constant):
            expression = pc
            taints = self.pc.taint

            def setstate(state, value):
                if taints:
                    state.platform.current_vm.pc = BitVecConstant(
                        size=256, value=value, taint=taints
                    )
                else:
                    state.platform.current_vm.pc = value

            raise Concretize("Symbolic PC", expression=expression, setstate=setstate, policy="ALL")
        try:
            self._check_jmpdest()
            last_pc, last_gas, instruction, arguments, fee, allocated = self._checkpoint()
            result = self._handler(*arguments)
            self._advance(result)
        except ConcretizeGas as ex:

            def setstate(state, value):
                state.platform.current._gas = value

            raise Concretize(
                "Concretize gas", expression=self._gas, setstate=setstate, policy="MINMAX"
            )
        except ConcretizeFee as ex:

            def setstate(state, value):
                current_vm = state.platform.current_vm
                (
                    _pc,
                    _old_gas,
                    _instruction,
                    _arguments,
                    _fee,
                    _allocated,
                ) = current_vm._checkpoint_data
                current_vm._checkpoint_data = (
                    _pc,
                    _old_gas,
                    _instruction,
                    _arguments,
                    value,
                    _allocated,
                )

            raise Concretize(
                "Concretize current instruction fee",
                expression=self._checkpoint_data[4],
                setstate=setstate,
                policy=ex.policy,
            )
        except ConcretizeArgument as ex:
            pos = ex.pos - 1

            def setstate(state, value):
                current_vm = state.platform.current_vm
                (
                    _pc,
                    _old_gas,
                    _instruction,
                    _arguments,
                    _fee,
                    _allocated,
                ) = current_vm._checkpoint_data
                new_arguments = []
                for old_arg in _arguments:
                    if len(new_arguments) == pos:
                        new_arguments.append(value)
                    else:
                        new_arguments.append(old_arg)
                current_vm._checkpoint_data = (
                    _pc,
                    _old_gas,
                    _instruction,
                    new_arguments,
                    _fee,
                    _allocated,
                )

            raise Concretize(
                "Concretize Instruction Argument",
                expression=arguments[pos],
                setstate=setstate,
                policy=ex.policy,
            )
        except NotEnoughGas:
            # If tried to pay gas and failed then consume all of it
            self._gas = 0
            raise
        except StartTx:
            raise
        except EndTx as ex:
            if isinstance(ex, Throw):
                self._gas = 0
            self._advance(exception=True)
            raise

    def read_buffer(self, offset, size):
        if issymbolic(size) and not isinstance(size, Constant):
            raise EVMException("Symbolic size not supported")
        if isinstance(size, Constant):
            size = size.value
        if size == 0:
            return b""
        self._allocate(offset, size)
        data = self.memory[offset : offset + size]
        return ArrayProxy(array=data)

    def write_buffer(self, offset, data):
        self._allocate(offset, len(data))
        for i, c in enumerate(data):
            self._store(offset + i, Operators.ORD(c))

    def _load(self, offset, size=1):
        value = self.memory.read_BE(offset, size)
        value = simplify(value)
        if isinstance(value, Constant) and not value.taint:
            value = value.value
        self._publish("did_evm_read_memory", offset, value, size)
        return value

    def _store(self, offset, value, size=1):
        """Stores value in memory as a big endian"""
        self.memory.write_BE(offset, value, size)
        self._publish("did_evm_write_memory", offset, value, size)

    def safe_add(self, a, b, *args):
        a = Operators.ZEXTEND(a, 512)
        b = Operators.ZEXTEND(b, 512)
        result = a + b
        if len(args) > 0:
            result = self.safe_add(result, *args)
        return result

    def safe_mul(self, a, b):
        a = Operators.ZEXTEND(a, 512)
        b = Operators.ZEXTEND(b, 512)
        result = a * b
        return result

    ############################################################################
    # INSTRUCTIONS

    def INVALID(self):
        """Halts execution"""
        self._throw()

    ############################################################################
    # Stop and Arithmetic Operations
    # All arithmetic is modulo 256 unless otherwise noted.

    def STOP(self):
        """Halts execution"""
        raise EndTx("STOP")

    def ADD(self, a, b):
        """Addition operation"""
        return a + b

    def MUL(self, a, b):
        """Multiplication operation"""
        return a * b

    def SUB(self, a, b):
        """Subtraction operation"""
        return a - b

    def DIV(self, a, b):
        """Integer division operation"""
        try:
            result = Operators.UDIV(a, b)
        except ZeroDivisionError:
            result = 0
        return Operators.ITEBV(256, b == 0, 0, result)

    def SDIV(self, a, b):
        """Signed integer division operation (truncated)"""
        s0, s1 = to_signed(a), to_signed(b)
        try:
            result = (
                Operators.ABS(s0)
                // Operators.ABS(s1)
                * Operators.ITEBV(256, (s0 < 0) != (s1 < 0), -1, 1)
            )
        except ZeroDivisionError:
            result = 0
        result = Operators.ITEBV(256, b == 0, 0, result)
        if not issymbolic(result):
            result = to_signed(result)
        return result

    def MOD(self, a, b):
        """Modulo remainder operation"""
        try:
            result = Operators.ITEBV(256, b == 0, 0, a % b)
        except ZeroDivisionError:
            result = 0
        return result

    def SMOD(self, a, b):
        """Signed modulo remainder operation"""
        s0, s1 = to_signed(a), to_signed(b)
        sign = Operators.ITEBV(256, s0 < 0, -1, 1)
        try:
            result = (Operators.ABS(s0) % Operators.ABS(s1)) * sign
        except ZeroDivisionError:
            result = 0

        return Operators.ITEBV(256, s1 == 0, 0, result)

    def ADDMOD(self, a, b, c):
        """Modulo addition operation"""
        try:
            result = Operators.EXTRACT(self.safe_add(a, b) % Operators.ZEXTEND(c, 512), 0, 256)
            result = Operators.ITEBV(256, c == 0, 0, result)
        except ZeroDivisionError:
            result = 0
        return result

    def MULMOD(self, a, b, c):
        """Modulo addition operation"""
        try:
            result = Operators.EXTRACT(self.safe_mul(a, b) % Operators.ZEXTEND(c, 512), 0, 256)
            result = Operators.ITEBV(256, c == 0, 0, result)
        except ZeroDivisionError:
            result = 0
        return result

    def EXP_gas(self, base, exponent):
        """Calculate extra gas fee"""
        EXP_SUPPLEMENTAL_GAS = 50  # cost of EXP exponent per byte

        def nbytes(e):
            result = 0
            for i in range(32):
                result = Operators.ITEBV(512, Operators.EXTRACT(e, i * 8, 8) != 0, i + 1, result)
            return result

        return EXP_SUPPLEMENTAL_GAS * nbytes(exponent)

    @concretized_args(base="SAMPLED", exponent="SAMPLED")
    def EXP(self, base, exponent):
        """
        Exponential operation
        The zero-th power of zero 0^0 is defined to be one.

        :param base: exponential base, concretized with sampled values
        :param exponent: exponent value, concretized with sampled values
        :return: BitVec* EXP result
        """
        if exponent == 0:
            return 1

        if base == 0:
            return 0

        return pow(base, exponent, TT256)

    def SIGNEXTEND(self, size, value):
        """Extend length of two's complement signed integer"""
        # FIXME maybe use Operators.SEXTEND
        testbit = Operators.ITEBV(256, size <= 31, size * 8 + 7, 257)
        result1 = value | (TT256 - (1 << testbit))
        result2 = value & ((1 << testbit) - 1)
        result = Operators.ITEBV(256, (value & (1 << testbit)) != 0, result1, result2)
        return Operators.ITEBV(256, size <= 31, result, value)

    ############################################################################
    # Comparison & Bitwise Logic Operations
    def LT(self, a, b):
        """Less-than comparison"""
        return Operators.ITEBV(256, Operators.ULT(a, b), 1, 0)

    def GT(self, a, b):
        """Greater-than comparison"""
        return Operators.ITEBV(256, Operators.UGT(a, b), 1, 0)

    def SLT(self, a, b):
        """Signed less-than comparison"""
        # http://gavwood.com/paper.pdf
        s0, s1 = to_signed(a), to_signed(b)
        return Operators.ITEBV(256, s0 < s1, 1, 0)

    def SGT(self, a, b):
        """Signed greater-than comparison"""
        # http://gavwood.com/paper.pdf
        s0, s1 = to_signed(a), to_signed(b)
        return Operators.ITEBV(256, s0 > s1, 1, 0)

    def EQ(self, a, b):
        """Equality comparison"""
        return Operators.ITEBV(256, a == b, 1, 0)

    def ISZERO(self, a):
        """Simple not operator"""
        return Operators.ITEBV(256, a == 0, 1, 0)

    def AND(self, a, b):
        """Bitwise AND operation"""
        return a & b

    def OR(self, a, b):
        """Bitwise OR operation"""
        return a | b

    def XOR(self, a, b):
        """Bitwise XOR operation"""
        return a ^ b

    def NOT(self, a):
        """Bitwise NOT operation"""
        return ~a

    def BYTE(self, offset, value):
        """Retrieve single byte from word"""
        offset = Operators.ITEBV(256, offset < 32, (31 - offset) * 8, 256)
        return Operators.ZEXTEND(Operators.EXTRACT(value, offset, 8), 256)

    def SHL(self, a, b):
        """Shift Left operation"""
        return b << a

    def SHR(self, a, b):
        """Logical Shift Right operation"""
        return b >> a

    def SAR(self, a, b):
        """Arithmetic Shift Right operation"""
        return Operators.SAR(256, b, a)

    def SHA3_gas(self, start, size):
        GSHA3WORD = 6  # Cost of SHA3 per word
        sha3fee = self.safe_mul(GSHA3WORD, ceil32(size) // 32)
        memfee = self._get_memfee(start, size)
        return self.safe_add(sha3fee, memfee)

    @concretized_args(size="ALL")
    def SHA3(self, start, size):
        """Compute Keccak-256 hash
        If the size is symbolic the potential solutions will be sampled as
        defined by the default policy and the analysis will be forked.
        The `size` can be considered concrete in this handler.

        """
        data = self.read_buffer(start, size)
        if consts.sha3 is consts.sha3.fake:
            func = globalfakesha3
        else:
            func = globalsha3
        return self.world.symbolic_function(func, data)

    ############################################################################
    # Environmental Information
    def ADDRESS(self):
        """Get address of currently executing account"""
        return self.address

    def BALANCE_gas(self, account):
        return 700  # BALANCE_SUPPLEMENTAL_GAS

    def BALANCE(self, account):
        """Get balance of the given account"""
        return self.world.get_balance(account)

    def SELFBALANCE(self):
        return self.world.get_balance(self.address)

    def ORIGIN(self):
        """Get execution origination address"""
        return Operators.ZEXTEND(self.world.tx_origin(), 256)

    def CALLER(self):
        """Get caller address"""
        return Operators.ZEXTEND(self.caller, 256)

    def CALLVALUE(self):
        """Get deposited value by the instruction/transaction responsible for this execution"""
        return self.value

    def CALLDATALOAD(self, offset):
        """Get input data of current environment"""
        # calldata_overflow = const.calldata_overflow
        calldata_overflow = None  # 32
        if calldata_overflow is not None:
            self.constraints.add(self.safe_add(offset, 32) <= len(self.data) + calldata_overflow)

        self._use_calldata(offset, 32)

        data_length = len(self.data)
        bytes = []
        for i in range(32):
            try:
                c = simplify(
                    Operators.ITEBV(
                        8,
                        Operators.ULT(self.safe_add(offset, i), data_length),
                        self.data[offset + i],
                        0,
                    )
                )
            except IndexError:
                # offset + i is concrete and outside data
                c = 0
            bytes.append(c)
        return Operators.CONCAT(256, *bytes)

    def _use_calldata(self, offset, size):
        """To improve reporting we maintain how much of the calldata is actually
        used. CALLDATACOPY and CALLDATA LOAD update this limit accordingly"""
        self._used_calldata_size = Operators.ITEBV(
            256, size != 0, self._used_calldata_size + offset + size, self._used_calldata_size
        )

    def CALLDATASIZE(self):
        """Get size of input data in current environment"""
        return len(self.data)

    def CALLDATACOPY_gas(self, mem_offset, data_offset, size):
        GCOPY = 3  # cost to copy one 32 byte word
        copyfee = self.safe_mul(GCOPY, self.safe_add(size, 31) // 32)
        memfee = self._get_memfee(mem_offset, size)
        return self.safe_add(copyfee, memfee)

    # @concretized_args(size="SAMPLED")
    def CALLDATACOPY(self, mem_offset, data_offset, size):
        """Copy input data in current environment to memory"""
        # calldata_overflow = const.calldata_overflow
        # calldata_underflow = const.calldata_underflow
        calldata_overflow = None  # 32
        if calldata_overflow is not None:
            self.constraints.add(
                Operators.ULT(self.safe_add(data_offset, size), len(self.data) + calldata_overflow)
            )

        self._use_calldata(data_offset, size)
        self._allocate(mem_offset, size)

        if consts.oog == "complete":
            # gas reduced #??
            cond = Operators.ULT(self.gas, self._checkpoint_data[1])
            self._publish("will_solve", self.constraints, cond, "can_be_true")
            enough_gas = SelectedSolver.instance().can_be_true(self.constraints, cond)
            self._publish("did_solve", self.constraints, cond, "can_be_true", enough_gas)
            if not enough_gas:
                raise NotEnoughGas()
            self.constraints.add(cond)

        if consts.calldata_max_size >= 0:
            self.constraints.add(Operators.ULE(size, consts.calldata_max_size))

        max_size = size
        if issymbolic(max_size):
            self._publish("will_solve", self.constraints, size, "max")
            max_size = SelectedSolver.instance().max(self.constraints, size)
            self._publish("did_solve", self.constraints, size, "max", max_size)

        if calldata_overflow is not None:
            cap = len(self.data) + calldata_overflow
            if max_size > cap:
                logger.info(f"Constraining CALLDATACOPY size to {cap}")
                max_size = cap
                self.constraints.add(Operators.ULE(size, cap))

        for i in range(max_size):
            try:
                c1 = Operators.ITEBV(
                    8,
                    Operators.ULT(self.safe_add(data_offset, i), len(self.data)),
                    Operators.ORD(self.data[data_offset + i]),
                    0,
                )

            except IndexError:
                # data_offset + i is concrete and outside data
                c1 = 0

            c = simplify(Operators.ITEBV(8, i < size, c1, self.memory[mem_offset + i]))
            if not issymbolic(c) or get_depth(c) < 3:
                x = c
            else:
                # if te expression is deep enough lets replace it by a binding
                x = self.constraints.new_bitvec(8, name="temp{}".format(uuid.uuid1()))
                self.constraints.add(x == c)
            self._store(mem_offset + i, x)

    def CODESIZE(self):
        """Get size of code running in current environment"""
        return len(self.bytecode)

    def CODECOPY_gas(self, mem_offset, code_offset, size):
        return self._get_memfee(mem_offset, size)

    @concretized_args(code_offset="SAMPLED", size="SAMPLED")
    def CODECOPY(self, mem_offset, code_offset, size):
        """Copy code running in current environment to memory"""

        self._allocate(mem_offset, size)
        GCOPY = 3  # cost to copy one 32 byte word
        copyfee = self.safe_mul(GCOPY, Operators.UDIV(self.safe_add(size, 31), 32))
        self._consume(copyfee)

        if issymbolic(size):
            self._publish("will_solve", self.constraints, size, "max")
            max_size = SelectedSolver.instance().max(self.constraints, size)
            self._publish("did_solve", self.constraints, size, "max", max_size)
        else:
            max_size = size

        for i in range(max_size):
            if issymbolic(i < size):
                default = Operators.ITEBV(
                    8, i < size, 0, self._load(mem_offset + i, 1)
                )  # Fixme. unnecessary memory read
            else:
                if i < size:
                    default = 0
                else:
                    default = self._load(mem_offset + i, 1)

            if issymbolic(code_offset):
                value = Operators.ITEBV(
                    8,
                    code_offset + i >= len(self.bytecode),
                    default,
                    self.bytecode[code_offset + i],
                )
            else:
                if code_offset + i >= len(self.bytecode):
                    value = default
                else:
                    value = self.bytecode[code_offset + i]
            self._store(mem_offset + i, value)
        self._publish("did_evm_read_code", self.address, code_offset, size)

    def GASPRICE(self):
        """Get price of gas in current environment"""
        return self.world.tx_gasprice()

    @concretized_args(account="ACCOUNTS")
    def EXTCODESIZE(self, account):
        """Get size of an account's code"""
        return len(self.world.get_code(account))

    @concretized_args(account="ACCOUNTS")
    def EXTCODEHASH(self, account):
        """Get hash of code"""
        bytecode = self.world.get_code(account)
        return globalsha3(bytecode)

    def EXTCODECOPY_gas(self, account, address, offset, size):
        GCOPY = 3  # cost to copy one 32 byte word
        extbytecode = self.world.get_code(account)
        memfee = self._get_memfee(address, size)
        return GCOPY * (ceil32(len(extbytecode)) // 32) + memfee

    @concretized_args(account="ACCOUNTS")
    def EXTCODECOPY(self, account, address, offset, size):
        """Copy an account's code to memory"""
        extbytecode = self.world.get_code(account)
        self._allocate(address + size)

        for i in range(size):
            if offset + i < len(extbytecode):
                self._store(address + i, extbytecode[offset + i])
            else:
                self._store(address + i, 0)
            self._publish("did_evm_read_code", address, offset, size)

    def RETURNDATACOPY_gas(self, mem_offset, return_offset, size):
        return self._get_memfee(mem_offset, size)

    def RETURNDATACOPY(self, mem_offset, return_offset, size):
        return_data = self._return_data

        self._allocate(mem_offset, size)
        for i in range(size):
            if return_offset + i < len(return_data):
                self._store(mem_offset + i, return_data[return_offset + i])
            else:
                self._store(mem_offset + i, 0)

    def RETURNDATASIZE(self):
        return len(self._return_data)

    ############################################################################
    # Block Information
    def BLOCKHASH(self, a):
        """Get the hash of one of the 256 most recent complete blocks"""
        return self.world.block_hash(a)

    def COINBASE(self):
        """Get the block's beneficiary address"""
        return self.world.block_coinbase()

    def TIMESTAMP(self):
        """Get the block's timestamp"""
        return self.world.block_timestamp()

    def NUMBER(self):
        """Get the block's number"""
        return self.world.block_number()

    def DIFFICULTY(self):
        """Get the block's difficulty"""
        return self.world.block_difficulty()

    def GASLIMIT(self):
        """Get the block's gas limit"""
        return self.world.block_gaslimit()

    def CHAINID(self):
        """Get current chainid."""
        #  1:= Ethereum Mainnet - https://chainid.network/
        return 1

    ############################################################################
    # Stack, Memory, Storage and Flow Operations
    def POP(self, a):
        """Remove item from stack"""
        # Items are automatically removed from stack
        # by the instruction dispatcher
        pass

    def MLOAD_gas(self, address):
        return self._get_memfee(address, 32)

    def MLOAD(self, address):
        """Load word from memory"""
        self._allocate(address, 32)
        value = self._load(address, 32)
        return value

    def MSTORE_gas(self, address, value):
        return self._get_memfee(address, 32)

    def MSTORE(self, address, value):
        """Save word to memory"""
        if istainted(self.pc):
            value = taint_with(value, *get_taints(self.pc))
        self._allocate(address, 32)
        self._store(address, value, 32)

    def MSTORE8_gas(self, address, value):
        return self._get_memfee(address, 1)

    def MSTORE8(self, address, value):
        """Save byte to memory"""
        if istainted(self.pc):
            for taint in get_taints(self.pc):
                value = taint_with(value, taint)
        self._allocate(address, 1)
        self._store(address, Operators.EXTRACT(value, 0, 8), 1)

    def SLOAD(self, offset):
        """Load word from storage"""
        storage_address = self.address
        self._publish("will_evm_read_storage", storage_address, offset)
        value = self.world.get_storage_data(storage_address, offset)
        self._publish("did_evm_read_storage", storage_address, offset, value)
        return value

    def SSTORE_gas(self, offset, value):
        storage_address = self.address
        SSSTORESENTRYGAS = (
            2300  # Minimum gas required to be present for an SSTORE call, not consumed
        )
        SSTORENOOP = 800  # Once per SSTORE operation if the value doesn't change.
        SSTOREDIRTYGAS = 800  # Once per SSTORE operation if a dirty value is changed.
        SSTOREINITGAS = 20000  # Once per SSTORE operation from clean zero to non-zero
        SstoreInitRefund = (
            19200  # Once per SSTORE operation for resetting to the original zero value
        )
        SSTORECLEANGAS = 5000  # Once per SSTORE operation from clean non-zero to something else
        SstoreCleanRefund = (
            4200  # Once per SSTORE operation for resetting to the original non-zero value
        )
        SstoreClearRefund = (
            15000  # Once per SSTORE operation for clearing an originally existing storage slot
        )

        self.fail_if(Operators.ULT(self.gas, SSSTORESENTRYGAS))

        # Get the storage from the snapshot took before this call
        try:
            original_value = self.world._callstack[-1][-2].get(offset, 0)
        except IndexError:
            original_value = 0

        current_value = self.world.get_storage_data(storage_address, offset)

        def ITE(*args):
            return Operators.ITEBV(512, *args)

        def AND(*args):
            return Operators.AND(*args)

        gascost = ITE(
            current_value == value,
            SSTORENOOP,
            ITE(
                original_value == current_value,
                ITE(original_value == 0, SSTOREINITGAS, SSTORECLEANGAS),
                SSTOREDIRTYGAS,
            ),
        )
        refund = 0
        refund += ITE(
            AND(
                current_value != value,
                original_value == current_value,
                original_value != 0,
                value == 0,
            ),
            SstoreClearRefund,
            0,
        )
        refund += ITE(
            AND(
                current_value != value,
                original_value != current_value,
                original_value != 0,
                current_value == 0,
            ),
            -SstoreClearRefund,
            0,
        )
        refund += ITE(
            AND(
                current_value != value,
                original_value != current_value,
                original_value != 0,
                current_value != 0,
                value == 0,
            ),
            SstoreClearRefund,
            0,
        )

        refund += ITE(
            AND(
                current_value != value,
                original_value != current_value,
                original_value == value,
                original_value == 0,
            ),
            SstoreInitRefund,
            0,
        )
        refund += ITE(
            AND(
                current_value != value,
                original_value != current_value,
                original_value == value,
                original_value != 0,
            ),
            SstoreCleanRefund,
            0,
        )
        self._refund += simplify(refund)
        return gascost

    def SSTORE(self, offset, value):
        """Save word to storage"""
        storage_address = self.address
        self._publish("will_evm_write_storage", storage_address, offset, value)

        if istainted(self.pc):
            for taint in get_taints(self.pc):
                value = taint_with(value, taint)
        self.world.set_storage_data(storage_address, offset, value)
        self._publish("did_evm_write_storage", storage_address, offset, value)

    def JUMP(self, dest):
        """Alter the program counter"""
        self.pc = dest
        # This set ups a check for JMPDEST in the next instruction
        self._set_check_jmpdest()

    def JUMPI(self, dest, cond):
        """Conditionally alter the program counter"""
        # TODO(feliam) If dest is Constant we do not need to 3 queries. There would
        # be only 2 options

        self.pc = Operators.ITEBV(256, cond != 0, dest, self.pc + self.instruction.size)
        # This set ups a check for JMPDEST in the next instruction if cond != 0
        self._set_check_jmpdest(cond != 0)

    def GETPC(self):
        """Get the value of the program counter prior to the increment"""
        return self.pc

    def MSIZE(self):
        """Get the size of active memory in bytes"""
        return self._allocated

    def GAS(self):
        """Get the amount of available gas, including the corresponding reduction the amount of available gas"""
        # fixme calculate gas consumption
        return self.gas

    def JUMPDEST(self):
        """Mark a valid destination for jumps"""

    ############################################################################
    # Push Operations
    def PUSH(self, value):
        """Place 1 to 32 bytes item on stack"""
        return value

    ############################################################################
    # Duplication Operations
    def DUP(self, *operands):
        """Duplicate stack item"""
        return (operands[-1],) + operands

    ############################################################################
    # Exchange Operations
    def SWAP(self, *operands):
        """Exchange 1st and 2nd stack items"""
        a = operands[0]
        b = operands[-1]
        return (b,) + operands[1:-1] + (a,)

    ############################################################################
    # Logging Operations
    def LOG_gas(self, address, size, *topics):
        return self._get_memfee(address, size)

    @concretized_args(size="ONE")
    def LOG(self, address, size, *topics):
        GLOGBYTE = 8
        self._consume(self.safe_mul(size, GLOGBYTE))
        memlog = self.read_buffer(address, size)
        self.world.log(self.address, topics, memlog)

    ############################################################################
    # System operations
    def CREATE_gas(self, value, offset, size):
        return self._get_memfee(offset, size)

    @transact
    def CREATE(self, value, offset, size):
        """Create a new account with associated code"""
        data = self.read_buffer(offset, size)
        self.world.start_transaction(
            "CREATE", None, data=data, caller=self.address, value=value, gas=self.gas * 63 // 64
        )
        raise StartTx()

    @CREATE.pos  # type: ignore
    def CREATE(self, value, offset, size):
        """Create a new account with associated code"""
        tx = self.world.last_transaction  # At this point last and current tx are the same.
        return tx.return_value

    def CALL_gas(self, wanted_gas, address, value, in_offset, in_size, out_offset, out_size):
        """Dynamic gas for CALL instruction. _arguably turing complete in itself_"""
        GCALLVALUE = 9000
        GCALLNEW = 25000
        wanted_gas = Operators.ZEXTEND(wanted_gas, 512)
        fee = Operators.ITEBV(512, value == 0, 0, GCALLVALUE)
        fee += Operators.ITEBV(
            512, Operators.OR(self.world.account_exists(address), value == 0), 0, GCALLNEW
        )
        fee += self._get_memfee(in_offset, in_size)

        exception = False
        available_gas = self._gas
        available_gas -= fee

        exception = Operators.OR(
            Operators.UGT(fee, self._gas),
            Operators.ULT(self.safe_mul(available_gas, 63), available_gas),
        )
        available_gas *= 63
        available_gas //= 64

        temp_call_gas = Operators.ITEBV(
            512, Operators.UGT(available_gas, wanted_gas), wanted_gas, available_gas
        )
        self._temp_call_gas = temp_call_gas
        return temp_call_gas + fee

    @transact
    @concretized_args(address="ACCOUNTS", in_offset="SAMPLED", in_size="SAMPLED")
    def CALL(self, gas, address, value, in_offset, in_size, out_offset, out_size):
        """Message-call into an account"""
        self.world.start_transaction(
            "CALL",
            address,
            data=self.read_buffer(in_offset, in_size),
            caller=self.address,
            value=value,
            gas=self._temp_call_gas + Operators.ITEBV(512, value != 0, 2300, 0),
        )
        raise StartTx()

    def __pos_call(self, out_offset, out_size):
        data = self._return_data
        data_size = len(data)
        size = Operators.ITEBV(256, Operators.ULT(out_size, data_size), out_size, data_size)
        self.write_buffer(out_offset, data[:size])
        self._get_memfee(out_offset, size)
        return self.world.transactions[-1].return_value

    @CALL.pos  # type: ignore
    def CALL(self, gas, address, value, in_offset, in_size, out_offset, out_size):
        return self.__pos_call(out_offset, out_size)

    def CALLCODE_gas(self, gas, address, value, in_offset, in_size, out_offset, out_size):
        return self._get_memfee(in_offset, in_size)

    @transact
    @concretized_args(in_offset="SAMPLED", in_size="SAMPLED")
    def CALLCODE(self, gas, _ignored_, value, in_offset, in_size, out_offset, out_size):
        """Message-call into this account with alternative account's code"""
        self.world.start_transaction(
            "CALLCODE",
            address=self.address,
            data=self.read_buffer(in_offset, in_size),
            caller=self.address,
            value=value,
            gas=gas,
        )
        raise StartTx()

    @CALLCODE.pos  # type: ignore
    def CALLCODE(self, gas, address, value, in_offset, in_size, out_offset, out_size):
        return self.__pos_call(out_offset, out_size)

    def RETURN_gas(self, offset, size):
        return self._get_memfee(offset, size)

    @concretized_args(size="SAMPLED")
    def RETURN(self, offset, size):
        """Halt execution returning output data"""
        data = self.read_buffer(offset, size)
        raise EndTx("RETURN", data)

    def DELEGATECALL_gas(self, gas, address, in_offset, in_size, out_offset, out_size):
        return self._get_memfee(in_offset, in_size)

    @transact
    @concretized_args(in_offset="SAMPLED", in_size="SAMPLED")
    def DELEGATECALL(self, gas, address, in_offset, in_size, out_offset, out_size):
        """Message-call into an account"""
        self.world.start_transaction(
            "DELEGATECALL",
            address,
            data=self.read_buffer(in_offset, in_size),
            caller=self.address,
            value=0,
            gas=gas,
        )
        raise StartTx()

    @DELEGATECALL.pos  # type: ignore
    def DELEGATECALL(self, gas, address, in_offset, in_size, out_offset, out_size):
        return self.__pos_call(out_offset, out_size)

    def STATICCALL_gas(self, gas, address, in_offset, in_size, out_offset, out_size):
        return self._get_memfee(in_offset, in_size)

    @transact
    @concretized_args(in_offset="SAMPLED", in_size="SAMPLED")
    def STATICCALL(self, gas, address, in_offset, in_size, out_offset, out_size):
        """Message-call into an account"""
        self.world.start_transaction(
            "CALL",
            address,
            data=self.read_buffer(in_offset, in_size),
            caller=self.address,
            value=0,
            gas=gas,
        )
        raise StartTx()

    @STATICCALL.pos  # type: ignore
    def STATICCALL(self, gas, address, in_offset, in_size, out_offset, out_size):
        return self.__pos_call(out_offset, out_size)

    def REVERT_gas(self, offset, size):
        return self._get_memfee(offset, size)

    def REVERT(self, offset, size):
        data = self.read_buffer(offset, size)
        # FIXME return remaining gas
        raise EndTx("REVERT", data)

    def THROW(self):
        # revert balance on CALL fail
        raise EndTx("THROW")

    def SELFDESTRUCT_gas(self, recipient):
        CreateBySelfdestructGas = 25000
        SelfdestructRefundGas = 24000
        fee = 0
        if not self.world.account_exists(recipient) and self.world.get_balance(self.address) != 0:
            fee += CreateBySelfdestructGas

        if self.address not in self.world._deleted_accounts:
            self._refund += SelfdestructRefundGas

        return fee

    @concretized_args(recipient="ACCOUNTS")
    def SELFDESTRUCT(self, recipient):
        """Halt execution and register account for later deletion"""
        # This may create a user account
        recipient = Operators.EXTRACT(recipient, 0, 160)
        address = self.address

        if recipient not in self.world:
            self.world.create_account(address=recipient)

        self.world.send_funds(address, recipient, self.world.get_balance(address))
        self.world.delete_account(address)

        raise EndTx("SELFDESTRUCT")

    def __str__(self):
        m = []
        for offset in range(128):
            # c = simplify(self.memory[offset])
            c = self.memory[offset]
            try:
                c = c.value
            except Exception:
                pass
            m.append(c)

        hd = _hexdump(m)

        result = ["-" * 147]
        pc = self.pc
        if isinstance(pc, Constant):
            pc = pc.value

        if issymbolic(pc):
            result.append("<Symbolic PC> {:s} {}\n".format(translate_to_smtlib(pc), pc.taint))
        else:
            operands_str = (
                self.instruction.has_operand and "0x{:x}".format(self.instruction.operand) or ""
            )
            result.append(
                "0x{:04x}: {:s} {:s} {:s}".format(
                    pc, self.instruction.name, operands_str, self.instruction.description
                )
            )

        args = {}
        implementation = getattr(self, self.instruction.semantics, None)
        if implementation is not None:
            args = dict(
                enumerate(
                    inspect.getfullargspec(implementation).args[1 : self.instruction.pops + 1]
                )
            )
        clmn = 80
        result.append(
            "Stack                                                                           Memory"
        )
        sp = 0
        for i in list(reversed(self.stack))[:10]:
            argname = args.get(sp, "")
            r = ""
            if issymbolic(i):
                r = "{:>12s} {:66s}".format(argname, repr(i))
            else:
                r = "{:>12s} 0x{:064x}".format(argname, i)
            sp += 1

            h = ""
            try:
                h = hd[sp - 1]
            except BaseException:
                pass
            r += " " * (clmn - len(r)) + h
            result.append(r)

        for i in range(sp, len(hd)):
            r = " " * clmn + hd[i]
            result.append(r)

        # Append gas
        gas = self.gas
        if issymbolic(gas):
            # gas = simplify(gas)
            result.append(f"Gas: {translate_to_smtlib(gas)[:20]} {gas.taint}")
        else:
            result.append(f"Gas: {gas}")

        return "\n".join(hex(self.address) + ": " + x for x in result)
