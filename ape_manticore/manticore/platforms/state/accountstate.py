from .storage import Storage
from typing import Optional, Set, Union, Dict, List
from ...core.smtlib import BitVec, Array, ConstraintSet, issymbolic, Operators
from .storage import Storage
from ape.api import ProviderAPI
from ..evm.exceptions import EVMException
from web3 import Web3


def toChecksumAddress(address: int):
    return Web3.toChecksumAddress(address)


class AccountState:
    def __init__(
        self,
        address: int,
        constraints: ConstraintSet,
        balance: Union[int, BitVec] = 0,
        nonce: Optional[Union[int, BitVec]] = None,
        storage: Optional[Union[Storage, Array]] = None,
        code: Optional[Union[bytes, Array]] = None,
        provider: Optional[ProviderAPI] = None,
    ) -> None:
        # create account
        self.address: int = address
        self.provider: Optional[ProviderAPI] = provider
        if nonce is None:
            self.nonce: Union[int, BitVec] = 1 if bool(code) else 0
        else:
            self.nonce: Union[int, BitVec] = nonce
        self.balance: Union[int, BitVec] = (
            Operators.ZEXTEND(balance, 512) if isinstance(balance, BitVec) else balance
        )
        self.storage: Union[Storage, Array] = (
            Storage(address, constraints) if storage is None else storage
        )
        self.code: Union[bytes, Array] = bytes() if code is None else code
        self.contraints = constraints

    def get_nonce(self) -> Union[int, BitVec]:
        if issymbolic(self.address):
            raise ValueError(f"Cannot retrieve the nonce of symbolic address {self.address}")
        if self.provider is not None:
            self.set_nonce(self.provider.get_nonce(toChecksumAddress(self.address)))
        return self.nonce

    def get_balance(self) -> Union[int, BitVec]:
        if self.provider is not None:
            return self.provider.get_balance(toChecksumAddress(self.address))
        return self.balance

    def has_storage(self) -> bool:
        if self.provider is not None:
            try:
                self.get_storage()
            except:
                raise NotImplemented
            return True
        return False

    def has_code(self) -> bool:
        return len(self.code) > 0

    def get_storage(self) -> Union[Storage, Array]:
        if self.provider is not None:
            self.set_storage(self.provider.get_storage(toChecksumAddress(self.address)))
        return self.storage

    def get_code(self) -> Union[bytes, Array]:
        if self.provider is not None:
            self.set_code(self.provider.get_code(toChecksumAddress(self.address)))
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
        # check if it already has a codehash
        if bool(self.code):
            raise EVMException("Code already set")
        self.code = code
