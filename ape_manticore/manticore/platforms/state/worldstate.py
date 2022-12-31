
from .storage import Storage
from typing import  Optional, Set, Union
from ...core.smtlib import (
    BitVec,
    ConstraintSet,
)


class WorldState:
    def is_remote(self) -> bool:
        return False

    def accounts(self) -> Set[int]:
        return set()

    def get_nonce(self, address: int) -> int:
        return 0

    def get_balance(self, address: int) -> int:
        return 0

    def has_storage(self, address: int) -> bool:
        return False

    def get_storage(self, address: int) -> Optional[Storage]:
        raise NotImplementedError

    def get_storage_data(
        self, constraints: ConstraintSet, address: int, offset: Union[int, BitVec]
    ) -> int:
        return 0

    def get_code(self, address: int) -> bytes:
        return bytes()

    def get_blocknumber(self) -> int:
        # assume initial byzantium block
        return 4370000

    def get_timestamp(self) -> int:
        # 1524785992; // Thu Apr 26 23:39:52 UTC 2018
        return 1524785992

    def get_difficulty(self) -> int:
        return 0

    def get_gaslimit(self) -> int:
        return 0

    def get_coinbase(self) -> int:
        return 0
