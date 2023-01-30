#!/usr/bin/env python3
import binascii
import random
import io
import copy
from typing import List, Set, Tuple, Union, Optional
from ape_manticore.manticore.core.smtlib.constraints import ConstraintSet
from ape_manticore.manticore.platforms.evm.exceptions import EVMException, EndTx, StartTx
from ape_manticore.manticore.platforms.state.blockheaderstate import BlockHeaderState
from ...platforms.platform import Platform
from ...core.smtlib import (
    SelectedSolver,
    BitVec,
    Array,
    ArrayProxy,
    Operators,
    Constant,
    translate_to_smtlib,
    simplify,
    issymbolic,
)
from ...core.state import Concretize, TerminateState
from ...core.smtlib.visitors import simplify
from ...exceptions import EthereumError
import sha3
import rlp
from .common import *
from .transaction import Transaction
import logging
from ..state.forkworldstate import WorldState
from ape.api import ProviderAPI
from .evm import EVM
from ..state.storage import Storage

logger = logging.getLogger(__name__)


class EVMWorld(Platform):
    _published_events = {
        "evm_read_storage",
        "evm_write_storage",
        "evm_read_code",
        "evm_write_code",
        "decode_instruction",
        "execute_instruction",
        "open_transaction",
        "close_transaction",
        "symbolic_function",
        "solve",
    }

    def __init__(
        self,
        constraints: ConstraintSet,
        provider: Optional[ProviderAPI] = None,
        fork=DEFAULT_FORK,
        **kwargs,
    ):
        super().__init__(path="NOPATH", **kwargs)
        self._world_state: WorldState = WorldState(constraints, provider)
        self._constraints: ConstraintSet = constraints
        self._callstack: List[
            Tuple[Transaction, List[EVMLog], Set[int], Optional[Storage], EVM]
        ] = []
        self._deleted_accounts: Set[int] = set()
        self._logs: List[EVMLog] = list()
        self._pending_transaction = None
        self._transactions: List[Transaction] = list()
        self._fork = fork
        self.start_block()

    def __getstate__(self):
        state = super().__getstate__()
        state["_pending_transaction"] = self._pending_transaction
        state["_logs"] = self._logs
        state["_world_state"] = self._world_state
        state["_constraints"] = self._constraints
        state["_callstack"] = self._callstack
        state["_deleted_accounts"] = self._deleted_accounts
        state["_transactions"] = self._transactions
        state["_fork"] = self._fork

        return state

    def __setstate__(self, state):
        super().__setstate__(state)
        self._constraints = state["_constraints"]
        self._pending_transaction = state["_pending_transaction"]
        self._world_state = state["_world_state"]
        self._deleted_accounts = state["_deleted_accounts"]
        self._logs = state["_logs"]
        self._callstack = state["_callstack"]
        self._transactions = state["_transactions"]
        self._fork = state["_fork"]

        for _, _, _, _, vm in self._callstack:
            self.forward_events_from(vm)

    def try_simplify_to_constant(self, data):
        concrete_data = bytearray()
        # for c in data:
        for index in range(len(data)):
            c = data[index]
            simplified = simplify(c)

            if isinstance(simplified, Constant):
                concrete_data.append(simplified.value)
            else:
                # simplify by solving. probably means that we need to improve simplification
                self._publish("will_solve", self.constraints, simplified, "get_all_values")
                solutions = SelectedSolver.instance().get_all_values(
                    self.constraints, simplified, 2, silent=True
                )
                self._publish(
                    "did_solve", self.constraints, simplified, "get_all_values", solutions
                )
                if len(solutions) != 1:
                    break
                concrete_data.append(solutions[0])
        else:
            data = bytes(concrete_data)
        return data

    def symbolic_function(self, func, data):
        """
        Get an unsound symbolication for function `func`

        """
        data = self.try_simplify_to_constant(data)
        try:
            result = []
            self._publish(
                "on_symbolic_function", func, data, result
            )  # This updates the local copy of result

            return result[0]
        except Exception as e:
            logger.info("Error! %r", e)
            self._publish("will_solve", self.constraints, data, "get_value")
            data_c = SelectedSolver.instance().get_value(self.constraints, data)
            self._publish("did_solve", self.constraints, data, "get_value", data_c)
            return int(sha3.keccak_256(data_c).hexdigest(), 16)

    @property
    def PC(self):
        return (self.current_vm.address, self.current_vm.pc)

    def __getitem__(self, index):
        assert isinstance(index, int)
        return self.accounts[index]

    def __contains__(self, key):
        assert not issymbolic(key), "Symbolic address not supported"
        return key in self.accounts

    def __str__(self):
        return (
            "WORLD:"
            + str(self._world_state)
            + "\n"
            + str(list((map(str, self.transactions))))
            + str(self.logs)
        )

    @property
    def logs(self):
        return self._logs

    @property
    def constraints(self):
        return self._constraints

    @constraints.setter
    def constraints(self, constraints):
        self._constraints = constraints
        if self.current_vm:
            self.current_vm.constraints = constraints

    @property
    def evmfork(self):
        return self._fork

    def _transaction_fee(self, sort, address, price, bytecode_or_data, caller, value):
        GTXCREATE = (
            32000  # Paid by all contract creating transactions after the Homestead transition.
        )
        GTXDATAZERO = 4  # Paid for every zero byte of data or code for a transaction.
        GTXDATANONZERO = 16  # Paid for every non - zero byte of data or code for a transaction.
        GTRANSACTION = 21000  # Paid for every transaction
        if sort == "CREATE":
            tx_fee = GTXCREATE
        else:
            tx_fee = GTRANSACTION  # Simple transaction fee

        zerocount = 0
        nonzerocount = 0
        if isinstance(bytecode_or_data, (Array, ArrayProxy)):
            # if nothing was written we can assume all elements are default to zero
            if len(bytecode_or_data.written) == 0:
                zerocount = len(bytecode_or_data)
        else:
            for index in range(len(bytecode_or_data)):
                try:
                    c = bytecode_or_data.get(index, 0)
                except AttributeError:
                    c = bytecode_or_data[index]

                zerocount += Operators.ITEBV(256, c == 0, 1, 0)
                nonzerocount += Operators.ITEBV(256, c == 0, 0, 1)

        tx_fee += zerocount * GTXDATAZERO
        tx_fee += nonzerocount * GTXDATANONZERO
        return simplify(tx_fee)

    def _make_vm_for_tx(self, tx):
        if tx.sort == "CREATE":
            bytecode = tx.data
            data = bytes()
        else:
            bytecode = self.get_code(tx.address)
            data = tx.data

        if tx.sort == "DELEGATECALL":
            # So at a DELEGATECALL the environment should look exactly the same as the original tx
            # This means caller, value and address are the same as prev tx
            assert tx.value == 0
            address = self.current_transaction.address
            caller = self.current_transaction.caller
            value = self.current_transaction.value
        else:
            address = tx.address
            caller = tx.caller
            value = tx.value

        gas = tx.gas

        vm = EVM(self._constraints, address, data, caller, value, bytecode, world=self, gas=gas)
        if self.depth == 0:
            # Only at human level we need to debit the tx_fee from the gas
            # In case of an internal tx the CALL-like instruction will
            # take the fee by itself
            tx_fee = self._transaction_fee(
                tx.sort, tx.address, tx.price, tx.data, tx.caller, tx.value
            )
            vm._consume(tx_fee)
        return vm

    def _open_transaction(self, sort, address, price, bytecode_or_data, caller, value, gas=None):
        """
        This try to opens a transaction.

        :param sort: CREATE, CALL, CALLCODE, STATICCALL, DELEGATECALL
        :param address: the destination address
        :param price: the gas price. Used at human transactions
        :param bytecode_or_data: the calldata or bytecode in creates
        :param caller: the caller account
        :param value: wei to transfer
        :param gas: gas budget
        :return: True if the transaction got accepted (enough balance to pay for stuff)
        """
        # sort
        if sort not in {"CALL", "CREATE", "DELEGATECALL", "CALLCODE", "STATICCALL"}:
            raise EVMException(f"Transaction type '{sort}' not supported")

        if caller not in self.accounts:
            logger.info("Caller not in account")
            raise EVMException(
                f"Caller account {hex(caller)} does not exist; valid accounts: {list(map(hex, self.accounts))}"
            )

        if sort == "CREATE":
            expected_address = self.new_address(sender=caller)
            if address is None:
                address = expected_address
            if address != expected_address:
                raise EthereumError(
                    f"Error: contract created from address {hex(caller)} with nonce {self.get_nonce(caller)} was expected to be at address {hex(expected_address)}, but create_contract was called with address={hex(address)}"
                )

        if address not in self.accounts:
            logger.info("Address does not exists creating it.")
            # Creating an unaccessible account
            self.create_account(address=address, nonce=int(sort != "CREATE"))

        tx = Transaction(
            sort, address, price, bytecode_or_data, caller, value, depth=self.depth, gas=gas
        )
        self._publish("will_open_transaction", tx)
        # Send the tx funds (We know there are enough at this point)
        if self.depth == 0:
            # Debit full gas budget in advance
            aux_price = Operators.ZEXTEND(tx.price, 512)
            aux_gas = Operators.ZEXTEND(tx.gas, 512)
            self.sub_from_balance(caller, aux_price * aux_gas)
        self.send_funds(tx.caller, tx.address, tx.value)

        if tx.address not in self.accounts:
            self.create_account(tx.address)

        # If not a human tx, reset returndata
        # https://github.com/ethereum/EIPs/blob/master/EIPS/eip-211.md
        if self.current_vm:
            self.current_vm._return_data = b""

        vm = self._make_vm_for_tx(tx)

        self._callstack.append(
            (tx, self.logs, self.deleted_accounts, copy.copy(self.get_storage(address)), vm)
        )
        self.forward_events_from(vm)
        self._publish("did_open_transaction", tx)
        return True

    def _close_transaction(self, result, data=None, rollback=False):
        self._publish("will_close_transaction", self._callstack[-1][0])
        tx, logs, deleted_accounts, account_storage, vm = self._callstack.pop()
        assert self.constraints == vm.constraints
        # Keep constraints gathered in the last vm
        self.constraints = vm.constraints

        # https://github.com/ethereum/EIPs/blob/master/EIPS/eip-211.md
        if data is not None and self.current_vm is not None:
            self.current_vm._return_data = data
        if rollback:
            self._set_storage(vm.address, account_storage)
            self._logs = logs
            # Return the transaction value
            self.send_funds(tx.address, tx.caller, tx.value)
        else:
            self._deleted_accounts = deleted_accounts
        self.increase_nonce(tx.caller)

        if result in {"THROW"}:
            unused_gas = 0
            refund = 0
        else:
            unused_gas = vm._gas
            refund = vm._refund

        used_gas = Operators.ZEXTEND(tx.gas, 512) - unused_gas
        refund = Operators.ITEBV(512, Operators.UGE(refund, used_gas // 2), used_gas // 2, refund)

        if tx.is_human:
            for deleted_account in self._deleted_accounts:
                self.delete_account(deleted_account)
            unused_fee = unused_gas * tx.price
            used_fee = used_gas * tx.price
            self.add_to_balance(tx.caller, unused_fee)
            self.add_to_balance(tx.caller, refund * tx.price)
            if self.block_coinbase() in self:
                self.add_to_balance(self.block_coinbase(), used_fee - refund * tx.price)
            else:
                logger.info(
                    "Coinbase not set. Throwing %r weis for the gas", used_fee - refund * tx.price
                )
        else:
            # if not rollback:
            # Refund unused gas to caller if
            self.current_vm._gas += unused_gas
            self.current_vm._refund += refund
        if tx.sort == "CREATE":
            if result in ("RETURN", "STOP"):
                # vm.consume(len(tx.return_data) * GCREATEDATAGAS)
                self.set_code(tx.address, data)
            else:
                self.delete_account(tx.address)

        tx.set_result(result, data, used_gas - refund)
        self._transactions.append(tx)
        self._publish("did_close_transaction", tx)

        if self.depth == 0:
            raise TerminateState(tx.result)

    @property
    def all_transactions(self):
        txs = tuple(self._transactions)
        return txs + tuple((x[0] for x in reversed(self._callstack)))

    @property
    def transactions(self):
        """Completed completed transaction"""
        return tuple(self._transactions)

    @property
    def human_transactions(self):
        """Completed human transaction"""
        txs = []
        for tx in self.transactions:
            if tx.depth == 0:
                txs.append(tx)
        return tuple(txs)

    @property
    def last_transaction(self):
        """Last completed transaction"""
        if len(self.transactions):
            return self.transactions[-1]
        return None

    @property
    def last_human_transaction(self):
        """Last completed human transaction"""
        for tx in reversed(self.transactions):
            if tx.depth == 0:
                return tx
        return None

    @property
    def current_vm(self):
        """current vm"""
        try:
            _, _, _, _, vm = self._callstack[-1]
            return vm
        except IndexError:
            return None

    @property
    def current_transaction(self):
        """current tx"""
        try:
            tx, _, _, _, _ = self._callstack[-1]
            if tx.result is not None:
                # That tx finished. No current tx.
                return None
            return tx
        except IndexError:
            return None

    @property
    def current_human_transaction(self):
        """Current ongoing human transaction"""
        try:
            tx, _, _, _, _ = self._callstack[0]
            if tx.result is not None:
                # That tx finished. No current tx.
                return None
            assert tx.depth == 0
            return tx
        except IndexError:
            return None

    @property
    def accounts(self) -> List[int]:
        return self._world_state.accounts()

    @property
    def normal_accounts(self) -> List[int]:
        accs = []
        for address in self.accounts:
            if len(self.get_code(address)) == 0:
                accs.append(address)
        return accs

    @property
    def contract_accounts(self) -> List[int]:
        accs = []
        for address in self.accounts:
            if len(self.get_code(address)) > 0:
                accs.append(address)
        return accs

    @property
    def deleted_accounts(self) -> Set[int]:
        return self._deleted_accounts

    def delete_account(self, address: int) -> None:
        self._world_state.delete_account(address)

    def get_storage_data(self, storage_address: int, offset: Union[int, BitVec]):
        """
        Read a value from a storage slot on the specified account

        :param storage_address: an account address
        :param offset: the storage slot to use.
        :type offset: int or BitVec
        :return: the value
        :rtype: int or BitVec
        """
        value = self._world_state.accounts_state[storage_address].storage.get(offset, 0)
        return simplify(value)

    def set_storage_data(
        self, storage_address: int, offset: Union[int, BitVec], value: Union[int, BitVec]
    ) -> None:
        """
        Writes a value to a storage slot in specified account

        :param storage_address: an account address
        :param offset: the storage slot to use.
        :type offset: int or BitVec
        :param value: the value to write
        :type value: int or BitVec
        """
        self._world_state.accounts_state[storage_address].storage.set(offset, value)

    def get_storage_items(self, address: int):
        """
        Gets all items in an account storage

        :param address: account address
        :return: all items in account storage. items are tuple of (index, value). value can be symbolic
        :rtype: list[(storage_index, storage_value)]
        """
        return self.get_storage(address).get_items()

    def has_storage(self, address: int) -> bool:
        """
        True if something has been written to the storage.
        Note that if a slot has been erased from the storage this function may
        lose any meaning.
        """
        return self._world_state.accounts_state[address].has_storage()

    def get_storage(self, address: int) -> Union[Storage, Array]:
        """
        Gets the storage of an account

        :param address: account address
        :return: account storage
        :rtype: bytearray or ArrayProxy
        """
        return self._world_state.accounts_state[address].get_storage()

    def _set_storage(self, address: int, storage: Union[Storage, Array]) -> None:
        """Private auxiliary function to replace the storage"""
        self._world_state.accounts_state[address].set_storage(storage)

    def get_nonce(self, address: int) -> Union[int, BitVec]:
        return self._world_state.accounts_state[address].get_nonce()

    def increase_nonce(self, address: int) -> Union[int, BitVec]:
        new_nonce = self.get_nonce(address) + 1
        self._world_state.accounts_state[address].set_nonce(new_nonce)
        return new_nonce

    def set_balance(self, address: int, value: Union[int, BitVec]) -> None:
        if isinstance(value, BitVec):
            value = Operators.ZEXTEND(value, 512)
        self._world_state.accounts_state[int(address)].set_balance(value)

    def get_balance(self, address: int) -> Union[int, BitVec]:
        if address not in self.accounts:
            return 0
        return Operators.EXTRACT(self._world_state.accounts_state[address].get_balance(), 0, 256)

    def account_exists(self, address: int) -> Union[bool, Union[int, BitVec]]:
        if address not in self.accounts:
            return False  # accounts default to nonexistent
        return (
            self.has_code(address)
            or Operators.UGT(self.get_nonce(address), 0)
            or Operators.UGT(self.get_balance(address), 0)
        )

    def add_to_balance(self, address: int, value: Union[int, BitVec]) -> None:
        if isinstance(value, BitVec):
            value = Operators.ZEXTEND(value, 512)
        old_value = self.get_balance(address)
        new_value = old_value + value
        self._world_state.accounts_state[address].set_balance(new_value)

    def sub_from_balance(self, address: int, value: Union[int, BitVec]) -> None:
        if isinstance(value, BitVec):
            value = Operators.ZEXTEND(value, 512)
        old_value = self.get_balance(address)
        new_value = old_value - value
        self._world_state.accounts_state[address].set_balance(new_value)

    def send_funds(self, sender: int, recipient: int, value: Union[int, BitVec]) -> None:
        if isinstance(value, BitVec):
            value = Operators.ZEXTEND(value, 512)
        self.sub_from_balance(sender, value)
        self.add_to_balance(recipient, value)

    def get_code(self, address: int) -> Union[bytes, Array]:
        if address not in self.accounts:
            return bytes()
        return self._world_state.accounts_state[address].get_code()

    def set_code(self, address, data):
        self._world_state.accounts_state[address].set_code(data)

    def has_code(self, address) -> bool:
        return self._world_state.accounts_state[address].has_code()

    def log(self, address, topics, data):
        self._logs.append(EVMLog(address, data, topics))
        logger.info("LOG %r %r", data, topics)

    def log_storage(self, addr):
        pass

    def add_refund(self, value):
        self._refund += value

    def sub_refund(self, value):
        self._refund -= value

    def block_prevhash(self):
        return 0

    # Block header related
    def start_block(
        self,
        blocknumber=4370000,
        timestamp=1524785992,
        difficulty=0x200,
        gaslimit=0x7FFFFFFF,
        coinbase=0,
    ):
        if coinbase not in self.accounts and coinbase != 0:
            logger.info("Coinbase account does not exists")
            self.create_account(coinbase)

        self._world_state.block_header_state.set_blocknumber(blocknumber)
        self._world_state.block_header_state.set_timestamp(timestamp)
        self._world_state.block_header_state.set_coinbase(coinbase)
        self._world_state.block_header_state.set_difficulty(difficulty)
        self._world_state.block_header_state.set_gaslimit(gaslimit)

    def end_block(self, block_reward=None):
        coinbase = self.block_coinbase()
        if coinbase not in self:
            raise EVMException("Coinbase not set")

        if block_reward is None:
            block_reward = 2000000000000000000  # 2 eth
        self.add_to_balance(self.block_coinbase(), block_reward)
        # self._block_header = None

    def block_coinbase(self) -> Union[int, BitVec]:
        return self._world_state.block_header_state.get_coinbase()

    def block_timestamp(self) -> Union[int, BitVec]:
        return self._world_state.block_header_state.get_blocknumber()

    def block_number(self) -> Union[int, BitVec]:
        return self._world_state.block_header_state.get_blocknumber()

    def block_difficulty(self) -> Union[int, BitVec]:
        return self._world_state.block_header_state.get_difficulty()

    def block_gaslimit(self) -> Union[int, BitVec]:
        return self._world_state.block_header_state.get_difficulty()

    def block_hash(self, block_number: Optional[int] = None, force_recent: bool = True):
        """
        Calculates a block's hash

        :param block_number: the block number for which to calculate the hash, defaulting to the most recent block
        :param force_recent: if True (the default) return zero for any block that is in the future or older than 256 blocks
        :return: the block hash
        """
        if block_number is None:
            block_number: Union[int, BitVec] = self.block_number() - 1

        # We are not maintaining an actual -block-chain- so we just generate
        # some hashes for each virtual block
        value = sha3.keccak_256((repr(block_number) + "NONCE").encode()).hexdigest()
        value = int(value, 16)

        if force_recent:
            # 0 is left on the stack if the looked for block number is greater or equal
            # than the current block number or more than 256 blocks behind the current
            # block. (Current block hash is unknown from inside the tx)
            bnmax = Operators.ITEBV(256, self.block_number() > 256, 256, self.block_number())
            value = Operators.ITEBV(
                256,
                Operators.OR(block_number >= self.block_number(), block_number < bnmax),
                0,
                value,
            )

        return value

    def tx_origin(self):
        if self.current_human_transaction:
            return self.current_human_transaction.caller

    def tx_gasprice(self):
        if self.current_human_transaction:
            return self.current_human_transaction.price

    @property
    def depth(self):
        return len(self._callstack)

    def new_address(self, sender=None, nonce=None):
        """Create a fresh 160bit address"""
        if sender is not None and nonce is None:
            nonce = self.get_nonce(sender)

        new_address = self.calculate_new_address(sender, nonce)
        if sender is None and new_address in self:
            return self.new_address(sender, nonce)
        return new_address

    @staticmethod
    def calculate_new_address(sender=None, nonce=None):
        if sender is None:
            # Just choose a random address for regular accounts:
            new_address = random.randint(100, pow(2, 160))
        elif issymbolic(sender):
            # TODO(Evan Sultanik): In the interim before we come up with a better solution,
            #                      consider breaking Yellow Paper comability and just returning
            #                      a random contract address here
            raise EthereumError(
                "Manticore does not yet support contracts with symbolic addresses creating new contracts"
            )
        else:
            if nonce is None:
                # assume that the sender is a contract account, which is initialized with a nonce of 1
                nonce = 1
            new_address = int(sha3.keccak_256(rlp.encode([sender, nonce])).hexdigest()[24:], 16)
        return new_address

    def execute(self):
        self._process_pending_transaction()
        if self.current_vm is None:
            raise TerminateState("Trying to execute an empty transaction", testcase=False)
        try:
            self.current_vm.execute()
        except StartTx:
            pass
        except EndTx as ex:
            self._close_transaction(ex.result, ex.data, rollback=ex.is_rollback())

    def create_account(self, address=None, balance=0, code=None, storage=None, nonce=None):
        """
        Low level account creation. No transaction is done.

        :param address: the address of the account, if known. If omitted, a new address will be generated as closely to the Yellow Paper as possible.
        :param balance: the initial balance of the account in Wei
        :param code: the runtime code of the account, if a contract
        :param storage: storage array
        :param nonce: the nonce for the account; contracts should have a nonce greater than or equal to 1
        """
        if address is None:
            address = self.new_address()

        if address in self.accounts:
            # FIXME account may have been created via selfdestruct destination
            # or CALL and may contain some ether already, though if it was a
            # selfdestructed address, it can not be reused
            raise EthereumError("The account already exists")

        self._world_state.add_account(address, balance, nonce, storage, code)

        # adds hash of new address
        data = binascii.unhexlify("{:064x}{:064x}".format(address, 0))
        value = sha3.keccak_256(data).hexdigest()
        value = int(value, 16)
        self._publish("on_concrete_sha3", data, value)

        return address

    def create_contract(self, price=0, address=None, caller=None, balance=0, init=None, gas=None):
        """
        Initiates a CREATE a contract account.
        Sends a transaction to initialize the contract.
        Do a world.run() after this to explore all _possible_ outputs

        :param address: the address of the new account, if known. If omitted, a new address will be generated as closely to the Yellow Paper as possible.
        :param balance: the initial balance of the account in Wei
        :param init: the initialization code of the contract

        The way that the Solidity compiler expects the constructor arguments to
        be passed is by appending the arguments to the byte code produced by the
        Solidity compiler. The arguments are formatted as defined in the Ethereum
        ABI2. The arguments are then copied from the init byte array to the EVM
        memory through the CODECOPY opcode with appropriate values on the stack.
        This is done when the byte code in the init byte array is actually run
        on the network.
        """
        self.start_transaction(
            "CREATE", address, price=price, data=init, caller=caller, value=balance, gas=gas
        )
        return address

    def transaction(self, address, price=0, data="", caller=None, value=0, gas=2300):
        """Initiates a CALL transaction on current state.
        Do a world.run() after this to explore all _possible_ outputs
        """
        self.start_transaction(
            "CALL", address, price=price, data=data, caller=caller, value=value, gas=gas
        )

    def start_transaction(
        self, sort, address, *, price=None, data=None, caller=None, value=0, gas=2300
    ):
        """
        Initiate a transaction.

        :param sort: the type of transaction. CREATE or CALL or DELEGATECALL
        :param address: the address of the account which owns the code that is executing.
        :param price: the price of gas in the transaction that originated this execution.
        :param data: the byte array that is the input data to this execution
        :param caller: the address of the account which caused the code to be executing. A 160-bit code used for identifying Accounts
        :param value: the value, in Wei, passed to this account as part of the same procedure as execution. One Ether is defined as being 10**18 Wei.
        :param bytecode: the byte array that is the machine code to be executed.
        :param gas: gas budget for this transaction.
        :param failed: True if the transaction must fail
        """
        assert self._pending_transaction is None, "Already started tx"
        assert caller is not None
        self._pending_transaction = PendingTransaction(
            sort, address, price, data, caller, value, gas, None
        )

    def _constraint_to_accounts(self, address, include_zero=False, ty="both"):
        if ty not in ("both", "normal", "contract"):
            raise ValueError("Bad account type. It must be `normal`, `contract` or `both`")
        if ty == "both":
            accounts = self.accounts
        elif ty == "normal":
            accounts = self.normal_accounts
        else:
            assert ty == "contract"
            accounts = self.contract_accounts

        # Constraint it so it can range over all accounts + address0
        cond = True
        if accounts:
            cond = None
            if include_zero:
                cond = address == 0

            for known_account in accounts:
                if cond is None:
                    cond = address == known_account
                else:
                    cond = Operators.OR(address == known_account, cond)
        return cond

    def _pending_transaction_concretize_address(self):
        sort, address, price, data, caller, value, gas, failed = self._pending_transaction
        if issymbolic(address):

            def set_address(state, solution):
                world = state.platform
                world._pending_transaction = (
                    sort,
                    solution,
                    price,
                    data,
                    caller,
                    value,
                    gas,
                    failed,
                )

            # Assuming this condition has at least one solution
            cond = self._constraint_to_accounts(address, ty="contract", include_zero=False)
            self.constraints.add(cond)

            raise Concretize(
                "Concretizing address on transaction",
                expression=address,
                setstate=set_address,
                policy="ALL",
            )

    def _pending_transaction_concretize_caller(self):
        sort, address, price, data, caller, value, gas, failed = self._pending_transaction
        if issymbolic(caller):

            def set_caller(state, solution):
                world = state.platform
                world._pending_transaction = (
                    sort,
                    address,
                    price,
                    data,
                    solution,
                    value,
                    gas,
                    failed,
                )

            # Constrain it so it can range over all normal accounts
            # TODO: document and log this is loosing completness
            cond = self._constraint_to_accounts(caller, ty="normal")

            self.constraints.add(cond)
            raise Concretize(
                "Concretizing caller on transaction",
                expression=caller,
                setstate=set_caller,
                policy="ALL",
            )

    def _pending_transaction_failed(self):
        sort, address, price, data, caller, value, gas, failed = self._pending_transaction

        # Initially the failed flag is not set. For now we need the caller to be
        # concrete so the caller balance is easy to get. Initialize falied here
        if failed is None:
            # Check depth
            failed = self.depth >= 1024
            # Fork on enough funds for value and gas
            if not failed:
                aux_src_balance = Operators.ZEXTEND(self.get_balance(caller), 512)
                aux_value = Operators.ZEXTEND(value, 512)
                enough_balance = Operators.UGE(aux_src_balance, aux_value)
                if self.depth == 0:
                    # take the gas from the balance
                    aux_price = Operators.ZEXTEND(price, 512)
                    aux_gas = Operators.ZEXTEND(gas, 512)
                    aux_fee = aux_price * aux_gas
                    # Iff a human tx debit the fee
                    enough_balance = Operators.AND(
                        enough_balance, Operators.UGE(aux_src_balance - aux_value, aux_fee)
                    )
                failed = Operators.NOT(enough_balance)
            self._pending_transaction = sort, address, price, data, caller, value, gas, failed

        if issymbolic(failed):
            # optimistic/pesimistic is inverted as the expresion represents fail
            policy = {"optimistic": "PESSIMISTIC", "pessimistic": "OPTIMISTIC"}.get(
                consts.txfail, "ALL"
            )

            def set_failed(state, solution):
                world = state.platform
                world._pending_transaction = (
                    sort,
                    address,
                    price,
                    data,
                    caller,
                    value,
                    gas,
                    solution,
                )

            raise Concretize(
                "Concretizing tx-fail on transaction",
                expression=failed,
                setstate=set_failed,
                policy=policy,
            )

        if self.depth != 0:
            price = 0
        aux_price = Operators.ZEXTEND(price, 512)
        aux_gas = Operators.ZEXTEND(gas, 512)
        tx_fee = Operators.ITEBV(512, self.depth == 0, aux_price * aux_gas, 0)
        aux_src_balance = Operators.ZEXTEND(self.get_balance(caller), 512)
        aux_value = Operators.ZEXTEND(value, 512)
        enough_balance = Operators.UGE(aux_src_balance, aux_value + tx_fee)
        return failed

    def _process_pending_transaction(self):
        # Nothing to do here if no pending transactions
        if self._pending_transaction is None:
            return
        sort, address, price, data, caller, value, gas, failed = self._pending_transaction
        # caller
        self._pending_transaction_concretize_caller()
        # to/address
        self._pending_transaction_concretize_address()
        # check onough balance for the value
        failed = self._pending_transaction_failed()

        # done concretizing stuff
        self._pending_transaction = None

        if not failed:
            self._open_transaction(sort, address, price, data, caller, value, gas=gas)
        else:
            tx = Transaction(
                sort, address, price, data, caller, value, depth=self.depth + 1, gas=gas
            )
            tx.set_result("TXERROR")
            self._transactions.append(tx)

    def dump(self, stream, state, mevm, message):
        from ...ethereum.manticore import calculate_coverage, flagged

        blockchain: EVMWorld = state.platform
        last_tx = blockchain.last_transaction

        stream.write("Message: %s\n" % message)
        stream.write("Last exception: %s\n" % state.context.get("last_exception", "None"))

        if last_tx and "evm.trace" in state.context:
            at_runtime = last_tx.sort != "CREATE"
            address, offset, at_init = state.context.get("evm.trace", ((None, None, None),))[-1]
            assert last_tx.result is not None or at_runtime != at_init

            # Last instruction if last tx was valid
            if str(state.context["last_exception"]) != "TXERROR":
                metadata = mevm.get_metadata(blockchain.last_transaction.address)
                if metadata is not None and address is not None:
                    stream.write("Last instruction at contract %x offset %x\n" % (address, offset))
                    source_code_snippet = metadata.get_source_for(offset, at_runtime)
                    if source_code_snippet:
                        stream.write("    ".join(source_code_snippet.splitlines(True)))
                    stream.write("\n")

        # Accounts summary
        assert state.can_be_true(True)
        is_something_symbolic = False
        stream.write("%d accounts.\n" % len(blockchain.accounts))
        for account_address in blockchain.accounts:
            is_account_address_symbolic = issymbolic(account_address)
            account_address = state.solve_one(account_address, constrain=True)

            stream.write("* %s::\n" % mevm.account_name(account_address))
            stream.write(
                "Address: 0x%x %s\n" % (account_address, flagged(is_account_address_symbolic))
            )
            balance = blockchain.get_balance(account_address)

            if not consts.ignore_balance:
                is_balance_symbolic = issymbolic(balance)
                is_something_symbolic = is_something_symbolic or is_balance_symbolic
                balance = state.solve_one(balance, constrain=True)
                stream.write("Balance: %d %s\n" % (balance, flagged(is_balance_symbolic)))

            storage = blockchain.get_storage(account_address)
            if isinstance(storage, Storage):
                stream = storage.dump(stream, state)
                stream.write("Storage: %s\n" % translate_to_smtlib(storage, use_bindings=False))

            # concrete_indexes = []
            # if len(storage.data.written) > 0:
            # concrete_indexes = state.solve_one_n_batched(storage.written, constrain=True)
            #
            # concrete_values = []
            # if len(concrete_indexes) > 0:
            # concrete_values = state.solve_one_n_batched(concrete_indexes, constrain=True)
            #
            # assert len(concrete_indexes) == len(concrete_values)
            # for index, value in zip(concrete_indexes, concrete_values):
            # stream.write(f"storage[{index:x}] = {value:x}\n")
            #
            # storage = blockchain.get_storage(account_address)
            # stream.write("Storage: %s\n" % translate_to_smtlib(storage, use_bindings=False))

            if consts.sha3 is consts.sha3.concretize:
                all_used_indexes = []
                with state.constraints as temp_cs:
                    # make a free symbolic idex that could address any storage slot
                    index = temp_cs.new_bitvec(256)
                    # get the storage for account_address
                    storage = blockchain.get_storage(account_address)
                    # we are interested only in used slots
                    # temp_cs.add(storage.get(index) != 0)
                    temp_cs.add(storage._data.is_known(index))
                    # Query the solver to get all storage indexes with used slots
                    self._publish("will_solve", temp_cs, index, "get_all_values")
                    all_used_indexes = SelectedSolver.instance().get_all_values(temp_cs, index)
                    self._publish("did_solve", temp_cs, index, "get_all_values", all_used_indexes)

                if all_used_indexes:
                    stream.write("Storage:\n")
                    for i in all_used_indexes:
                        value = storage.get(i)
                        is_storage_symbolic = issymbolic(value)
                        stream.write(
                            "storage[%x] = %x %s\n"
                            % (
                                state.solve_one(i, constrain=True),
                                state.solve_one(value, constrain=True),
                                flagged(is_storage_symbolic),
                            )
                        )

            runtime_code = state.solve_one(blockchain.get_code(account_address))
            if runtime_code:
                stream.write("Code:\n")
                fcode = io.BytesIO(runtime_code)
                for chunk in iter(lambda: fcode.read(32), b""):
                    stream.write("\t%s\n" % binascii.hexlify(chunk))
                runtime_trace = set(
                    (
                        pc
                        for contract, pc, at_init in state.context["evm.trace"]
                        if address == contract and not at_init
                    )
                )
                stream.write(
                    "Coverage %d%% (on this state)\n"
                    % calculate_coverage(runtime_code, runtime_trace)
                )  # coverage % for address in this account/state
            stream.write("\n")
        return is_something_symbolic
