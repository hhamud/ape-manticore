from ape_manticore.manticore.platforms.state.provider import ProviderAPI
from .worldstate import EmptyWorldState
from .storage import Storage
from typing import Optional, Set, Union, Dict, List
from ...core.smtlib import BitVec, Array, ConstraintSet, issymbolic
from ape.api import ProviderAPI


class AccountState:
    def __init__(self, provider: Optional[ProviderAPI]) -> None:
        self.provider = provider
        self.nonce: Union[int, BitVec] = 0
        self.balance: Union[int, BitVec] = 0
        self.storage: Union[Storage, Array] = Array()
        self.code: Union[bytes, Array] = bytes()

    def __setitem__(self):
        pass

    def get_nonce(self, address: int) -> Union[int, BitVec]:
        if issymbolic(address):
            raise ValueError(f"Cannot retrieve the nonce of symbolic address {address}")
        if self.provider is not None:
            return self.provider.get_nonce(str(address))
        else:
            return self.nonce

    def get_balance(self, address: int) -> Union[int, BitVec]:
        if self.provider is not None:
            return self.provider.get_balance(str(address))
        else:
            return self.balance

    def has_storage(self, address: int) -> bool:
        pass

    def get_storage(self, address: int) -> Union[Storage, Array]:
        if self.provider is not None:
            return self.provider.get_storage(str(address))
        return self.storage

    def get_code(self, address: int) -> Union[bytes, Array]:
        if self.provider is not None:
            return self.provider.get_code(str(address))
        else:
            return self.code

    def set_nonce(self, value: Union[int, BitVec]) -> None:
        self.nonce = value

    def set_balance(self, value: Union[int, BitVec]) -> None:
        self.balance = value

    def set_storage(self, storage: Optional[Storage]) -> None:
        self.storage = storage

    def set_storage_data(
        self,
        constraints: ConstraintSet,
        address: int,
        offset: Union[int, BitVec],
        value: Union[int, BitVec],
    ):
        storage = self.storage.get(address)
        if storage is None:
            storage = Storage(constraints, address)
            self.storage = storage
        storage.set(offset, value)

    def set_code(self, code: Union[bytes, Array]) -> None:
        self.code = code
