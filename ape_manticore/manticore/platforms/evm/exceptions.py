#!/usr/bin/env python3


# Exceptions...
class EVMException(Exception):
    pass


class ConcretizeArgument(EVMException):
    """
    Raised when a symbolic argument needs to be concretized.
    """

    def __init__(self, pos, expression=None, policy="SAMPLED"):
        self.message = "Concretizing evm stack item {}".format(pos)
        self.pos = pos
        self.expression = expression
        self.policy = policy


class ConcretizeFee(EVMException):
    """
    Raised when a symbolic gas fee needs to be concretized.
    """

    def __init__(self, policy="MINMAX"):
        self.message = "Concretizing evm instruction gas fee"
        self.policy = policy


class ConcretizeGas(EVMException):

    """
    Raised when a symbolic gas needs to be concretized.
    """

    def __init__(self, policy="MINMAX"):
        self.message = "Concretizing evm gas"
        self.policy = policy


class StartTx(EVMException):
    """A new transaction is started"""

    pass


class EndTx(EVMException):
    """The current transaction ends"""

    def __init__(self, result, data=None):
        if result not in {None, "TXERROR", "REVERT", "RETURN", "THROW", "STOP", "SELFDESTRUCT"}:
            raise EVMException("Invalid end transaction result")
        if result is None and data is not None:
            raise EVMException("Invalid end transaction result")
        if not isinstance(data, (type(None), Array, bytes)):
            raise EVMException("Invalid end transaction data type")
        self.result = result
        self.data = data

    def is_rollback(self):
        if self.result in {"STOP", "RETURN", "SELFDESTRUCT"}:
            return False
        else:
            assert self.result in {"THROW", "TXERROR", "REVERT"}
            return True

    def __str__(self):
        return f"EndTX<{self.result}>"


class Throw(EndTx):
    def __init__(self):
        super().__init__("THROW")


class InvalidOpcode(Throw):
    """Trying to execute invalid opcode"""


class StackOverflow(Throw):
    """Attempted to push more than 1024 items"""

    pass


class StackUnderflow(Throw):
    """Attempted to pop from an empty stack"""

    pass


class NotEnoughGas(Throw):
    """Not enough gas for operation"""

    pass


class Stop(EndTx):
    """Program reached a STOP instruction"""

    def __init__(self):
        super().__init__("STOP")


class Return(EndTx):
    """Program reached a RETURN instruction"""

    def __init__(self, data=bytes()):
        super().__init__("RETURN", data)


class Revert(EndTx):
    """Program reached a REVERT instruction"""

    def __init__(self, data):
        super().__init__("REVERT", data)


class SelfDestruct(EndTx):
    """Program reached a SELFDESTRUCT instruction"""

    def __init__(self):
        super().__init__("SELFDESTRUCT")


class TXError(EndTx):
    """A failed Transaction"""

    def __init__(self):
        super().__init__("TXERROR")
