#!/usr/bin/env python3
import inspect
from functools import wraps
from ...core.smtlib import (
    BitVec,
    Operators,
    Constant,
    issymbolic,
)
import logging
from collections import namedtuple
import sha3
from ...utils import config
from .exceptions import ConcretizeArgument

logger = logging.getLogger(__name__)


consts = config.get_group("evm")
DEFAULT_FORK = "istanbul"


def globalsha3(data):
    if issymbolic(data):
        return None
    return int(sha3.keccak_256(data).hexdigest(), 16)


def globalfakesha3(data):
    return None


consts.add(
    "oog",
    default="ignore",
    description=(
        "Default behavior for symbolic gas."
        "pedantic: Fully faithful. Test at every instruction. Forks."
        "complete: Mostly faithful. Test at BB limit. Forks."
        "concrete: Incomplete. Concretize gas to MIN/MAX values. Forks."
        "optimistic: Try to not fail due to OOG. If it can be enough gas use it. Ignore the path to OOG. Wont fork"
        "pesimistic: Try OOG asap. Fail soon. Ignore the path with enough gas."
        "ignore: Ignore gas. Instructions won't consume gas"
    ),
)

consts.add(
    "txfail",
    default="optimistic",
    description=(
        "Default behavior for transaction failing because not enough funds."
        "optimistic: Assume there is always enough funds to pay for value and gas. Wont fork"
        "pessimistic: Assume the balance is never enough for paying fo a transaction. Wont fork"
        "both: Will fork for both options if possible."
    ),
)

consts.add(
    "calldata_max_offset",
    default=1024 * 1024,
    description="Max calldata offset to explore with. Iff offset or size in a calldata related instruction are symbolic it will be constrained to this constant",
)
consts.add(
    "calldata_max_size",
    default=-1,
    description="Max calldata size to explore in each CALLDATACOPY. Iff size in a calldata related instruction are symbolic it will be constrained to be less than this constant. -1 means free(only use when gas is being tracked)",
)
consts.add(
    "ignore_balance",
    default=False,
    description="Do not try to solve symbolic balances",
)


# Auxiliary constants and functions
TT256 = 2**256
TT256M1 = 2**256 - 1
MASK160 = 2**160 - 1
TT255 = 2**255
TOOHIGHMEM = 0x1000
DEFAULT_FORK = "istanbul"

# FIXME. We should just use a Transaction() for this
PendingTransaction = namedtuple(
    "PendingTransaction", ["type", "address", "price", "data", "caller", "value", "gas", "failed"]
)
EVMLog = namedtuple("EVMLog", ["address", "memlog", "topics"])


def ceil32(x):
    size = 256
    if isinstance(x, BitVec):
        size = x.size
    return Operators.ITEBV(size, Operators.UREM(x, 32) == 0, x, x + 32 - Operators.UREM(x, 32))


def to_signed(i):
    return Operators.ITEBV(256, i < TT255, i, i - TT256)


def concretized_args(**policies):
    r"""
    Make sure an EVM instruction has all of its arguments concretized according to
    provided policies.

    Example decoration:

        @concretized_args(size='ONE', address='')
        def LOG(self, address, size, \*topics):
        ...

    The above will make sure that the *size* parameter to LOG is Concretized when symbolic
    according to the 'ONE' policy and concretize *address* with the default policy.

    :param policies: A kwargs list of argument names and their respective policies.
                         Provide None or '' as policy to use default.
    :return: A function decorator
    """

    def concretizer(func):
        spec = inspect.getfullargspec(func)

        @wraps(func)
        def wrapper(*args, **kwargs):
            for arg, policy in policies.items():
                assert arg in spec.args, "Concretizer argument not found in wrapped function."
                # index is 0-indexed, but ConcretizeArgument is 1-indexed. However, this is correct
                # since implementation method is always a bound method (self is param 0)
                index = spec.args.index(arg)
                if not issymbolic(args[index]) or isinstance(args[index], Constant):
                    continue
                if not policy:
                    policy = "SAMPLED"

                if policy == "ACCOUNTS":
                    value = args[index]
                    world = args[0].world
                    # special handler for EVM only policy
                    cond = world._constraint_to_accounts(value, ty="both", include_zero=True)
                    world.constraints.add(cond)
                    policy = "ALL"

                if args[index].taint:
                    # TODO / FIXME: The taint should persist!
                    logger.warning(
                        f"Concretizing {func.__name__}'s {index} argument and dropping its taints: "
                        "the value might not be tracked properly (This may affect detectors)"
                    )
                logger.info(
                    f"Concretizing instruction {args[0].world.current_vm.instruction} argument {arg} by {policy}"
                )

                raise ConcretizeArgument(index, policy=policy)
            return func(*args, **kwargs)

        wrapper.__signature__ = inspect.signature(func)
        return wrapper

    return concretizer


_FILTER = "".join((len(repr(chr(x))) == 3) and chr(x) or "." for x in range(256))


def _hexdump(src, length=16):
    lines = []
    for c in range(0, len(src), length):
        chars = src[c : c + length]

        def p(x):
            if issymbolic(x):
                return "??"
            else:
                return "%02x" % x

        hex = " ".join(p(x) for x in chars)

        def p1(x):
            if issymbolic(x):
                return "."
            else:
                return "%s" % ((x <= 127 and _FILTER[x]) or ".")

        printable = "".join(p1(x) for x in chars)
        lines.append("%04x  %-*s  %s" % (c, length * 3, hex, printable))
    return lines
