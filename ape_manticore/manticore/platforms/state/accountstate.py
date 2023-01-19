from ape_manticore.manticore.platforms.state.provider import ProviderAPI
from .worldstate import EmptyWorldState
from .storage import Storage
from typing import Optional, Set, Union, Dict, List
from ...core.smtlib import BitVec, Array, ConstraintSet, issymbolic
from .storage import Storage
from ape.api import ProviderAPI


class AccountState:
    def __init__(
        self, address: int, constraints: ConstraintSet, provider: Optional[ProviderAPI] = None
    ) -> None:
        self.address = address
        self.provider = provider
        self.nonce: Union[int, BitVec] = 0
        self.balance: Union[int, BitVec] = 0
        self.storage: Union[Storage, Array] = Storage(address, constraints)
        self.code: Union[bytes, Array] = bytes()

    def get_nonce(self) -> Union[int, BitVec]:
        if issymbolic(self.address):
            raise ValueError(f"Cannot retrieve the nonce of symbolic address {self.address}")
        if self.provider is not None:
            self.set_nonce(self.provider.get_nonce(str(self.address)))
        return self.nonce

    def get_balance(self) -> Union[int, BitVec]:
        if self.provider is not None:
            self.set_balance(self.provider.get_balance(str(self.address)))
        return self.balance

    def has_storage(self) -> bool:
        if self.provider is not None:
            try:
                self.get_storage()
            except:
                raise NotImplemented
            return True
        return False

    def get_storage(self) -> Union[Storage, Array]:
        if self.provider is not None:
            self.set_storage(self.provider.get_storage(str(self.address)))
        return self.storage

    def get_code(self) -> Union[bytes, Array]:
        if self.provider is not None:
            self.set_code(self.provider.get_code(str(self.address)))
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
        offset: Union[int, BitVec],
        value: Union[int, BitVec],
    ) -> None:
        storage = self.storage.get(offset, value)

        if storage is None:
            storage = Storage(self.address, constraints)
            self.storage = storage
        storage.set(offset, value)

    def set_code(self, code: Union[bytes, Array]) -> None:
        self.code = code
