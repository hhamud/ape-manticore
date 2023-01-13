#!/usr/bin/env python3
import binascii
from ...core.smtlib import (
    BitVec,
    Array,
    issymbolic,
)
from ...utils.helpers import printable_bytes


class Transaction:
    __slots__ = (
        "_sort",
        "address",
        "price",
        "data",
        "caller",
        "value",
        "depth",
        "_return_data",
        "_result",
        "gas",
        "_used_gas",
    )

    def __init__(
        self,
        sort,
        address,
        price,
        data,
        caller,
        value,
        gas=0,
        depth=None,
        result=None,
        return_data=None,
        used_gas=None,
    ):
        self.sort = sort
        self.address = address
        self.price = price
        self.data = data
        self.caller = caller
        self.value = value
        self.depth = depth
        self.gas = gas
        self.set_result(result, return_data, used_gas)

    def concretize(self, state, constrain=False):
        """
        :param state: a manticore state
        :param bool constrain: If True, constrain expr to concretized value
        """
        all_elems = [
            self.caller,
            self.address,
            self.value,
            self.gas,
            self.data,
            self._return_data,
            self.used_gas,
        ]
        values = state.solve_one_n_batched(all_elems, constrain=constrain)
        conc_caller = values[0]
        conc_address = values[1]
        conc_value = values[2]
        conc_gas = values[3]
        conc_data = values[4]
        conc_return_data = values[5]
        conc_used_gas = values[6]

        return Transaction(
            self.sort,
            conc_address,
            self.price,
            conc_data,
            conc_caller,
            conc_value,
            conc_gas,
            depth=self.depth,
            result=self.result,
            return_data=conc_return_data,
        )

    def to_dict(self, mevm):
        """
        Only meant to be used with concrete Transaction objects! (after calling .concretize())
        """
        return dict(
            type=self.sort,
            from_address=self.caller,
            from_name=mevm.account_name(self.caller),
            to_address=self.address,
            to_name=mevm.account_name(self.address),
            value=self.value,
            gas=self.gas,
            data=binascii.hexlify(self.data).decode(),
            used_gas=self.used_gas,
        )

    def dump(self, stream, state, mevm, conc_tx=None):
        """
        Concretize and write a human readable version of the transaction into the stream. Used during testcase
        generation.

        :param stream: Output stream to write to. Typically a file.
        :param manticore.ethereum.State state: state that the tx exists in
        :param manticore.ethereum.ManticoreEVM mevm: manticore instance
        :return:
        """
        from ...ethereum import ABI  # circular imports
        from ...ethereum.manticore import flagged

        is_something_symbolic = False

        if conc_tx is None:
            conc_tx = self.concretize(state)

        # The result if any RETURN or REVERT
        stream.write("Type: %s (%d)\n" % (self.sort, self.depth))

        caller_solution = conc_tx.caller

        caller_name = mevm.account_name(caller_solution)
        stream.write(
            "From: %s(0x%x) %s\n" % (caller_name, caller_solution, flagged(issymbolic(self.caller)))
        )

        address_solution = conc_tx.address
        address_name = mevm.account_name(address_solution)

        stream.write(
            "To: %s(0x%x) %s\n"
            % (address_name, address_solution, flagged(issymbolic(self.address)))
        )
        stream.write("Value: %d %s\n" % (conc_tx.value, flagged(issymbolic(self.value))))
        stream.write("Gas used: %d %s\n" % (conc_tx.gas, flagged(issymbolic(self.gas))))

        tx_data = conc_tx.data
        if len(tx_data) > 80:
            tx_data = tx_data.rstrip(conc_tx.data[-3:-1])

        stream.write(
            "Data: 0x{} {}\n".format(
                binascii.hexlify(tx_data).decode(), flagged(issymbolic(self.data))
            )
        )

        if self.return_data is not None:
            return_data = conc_tx.return_data

            stream.write(
                "Return_data: 0x{} {} {}\n".format(
                    binascii.hexlify(return_data).decode(),
                    f"({printable_bytes(return_data)})" if conc_tx.sort != "CREATE" else "",
                    flagged(issymbolic(self.return_data)),
                )
            )

        metadata = mevm.get_metadata(self.address)
        if self.sort == "CREATE":
            if metadata is not None:

                conc_args_data = conc_tx.data[len(metadata._init_bytecode) :]
                arguments = ABI.deserialize(metadata.get_constructor_arguments(), conc_args_data)

                # TODO confirm: arguments should all be concrete?

                is_argument_symbolic = any(
                    map(issymbolic, arguments)
                )  # is this redundant since arguments are all concrete?
                stream.write("Function call:\n")
                stream.write("Constructor(")
                stream.write(",".join(map(repr, arguments)))
                stream.write(") -> %s %s\n" % (self.result, flagged(is_argument_symbolic)))

        if self.sort == "CALL":
            if metadata is not None:
                calldata = conc_tx.data
                is_calldata_symbolic = issymbolic(self.data)

                function_id = bytes(calldata[:4])  # hope there is enough data
                signature = metadata.get_func_signature(function_id)
                function_name = metadata.get_func_name(function_id)
                if signature:
                    _, arguments = ABI.deserialize(signature, calldata)
                else:
                    arguments = (calldata,)

                return_data = None
                if self.result == "RETURN":
                    ret_types = metadata.get_func_return_types(function_id)
                    return_data = conc_tx.return_data
                    return_values = ABI.deserialize(ret_types, return_data)  # function return

                is_return_symbolic = issymbolic(self.return_data)

                stream.write("\n")
                stream.write("Function call:\n")
                stream.write("%s(" % function_name)
                stream.write(",".join(map(repr, arguments)))
                stream.write(") -> %s %s\n" % (self.result, flagged(is_calldata_symbolic)))

                if return_data is not None:
                    if len(return_values) == 1:
                        return_values = return_values[0]

                    stream.write("return: %r %s\n" % (return_values, flagged(is_return_symbolic)))
                is_something_symbolic = is_calldata_symbolic or is_return_symbolic

        stream.write("\n\n")
        return is_something_symbolic

    @property
    def sort(self):
        return self._sort

    @sort.setter
    def sort(self, sort):
        if sort not in {"CREATE", "CALL", "CALLCODE", "DELEGATECALL"}:
            raise EVMException(f"Invalid transaction type: {sort}")
        self._sort = sort

    @property
    def result(self):
        return self._result

    @property
    def is_human(self):
        """
        Returns whether this is a transaction made by human (in a script).

        As an example for:
            contract A { function a(B b) { b.b(); } }
            contract B { function b() {} }

        Calling `B.b()` makes a human transaction.
        Calling `A.a(B)` makes a human transaction which makes an internal transaction (b.b()).
        """
        return self.depth == 0

    @property
    def return_data(self):
        return self._return_data

    @property
    def return_value(self):
        if self.result in {"RETURN", "STOP", "SELFDESTRUCT"}:
            if self.sort == "CREATE":
                return self.address
            else:
                return 1
        else:
            assert self.result in {"TXERROR", "REVERT", "THROW"}
            return 0

    @property
    def used_gas(self):
        return self._used_gas

    def set_result(self, result, return_data=None, used_gas=None):
        if getattr(self, "result", None) is not None:
            raise EVMException("Transaction result already set")
        if not isinstance(used_gas, (int, BitVec, type(None))):
            raise EVMException("Invalid used gas in Transaction")
        if result not in {None, "TXERROR", "REVERT", "RETURN", "THROW", "STOP", "SELFDESTRUCT"}:
            raise EVMException("Invalid transaction result")
        if result in {"RETURN", "REVERT"}:
            if not isinstance(return_data, (bytes, bytearray, Array)):
                raise EVMException(
                    "Invalid transaction return_data type:", type(return_data).__name__
                )
        elif result in {"STOP", "THROW", "SELFDESTRUCT"}:
            if return_data is None:
                return_data = b""
            if not isinstance(return_data, (bytes, bytearray, Array)) or len(return_data) != 0:
                raise EVMException(
                    f"Invalid transaction return_data. Too much data ({len(return_data)}) for STOP, THROW or SELFDESTRUCT"
                )
        else:
            if return_data is not None:
                raise EVMException("Invalid transaction return_data")
        self._result = result
        self._return_data = return_data
        self._used_gas = used_gas

    def __reduce__(self):
        """Implements serialization/pickle"""
        return (
            self.__class__,
            (
                self.sort,
                self.address,
                self.price,
                self.data,
                self.caller,
                self.value,
                self.gas,
                self.depth,
                self.result,
                self.return_data,
                self.used_gas,
            ),
        )

    def __str__(self):
        return "Transaction({:s}, from=0x{:x}, to=0x{:x}, value={!r}, depth={:d}, data={!r}, result={!r}, gas={!r} ..)".format(
            self.sort,
            self.caller,
            self.address,
            self.value,
            self.depth,
            self.data,
            self.result,
            self.gas,
        )
