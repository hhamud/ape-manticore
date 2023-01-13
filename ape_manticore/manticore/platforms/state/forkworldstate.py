from .worldstate import EmptyWorldState
from .storage import Storage
from typing import Optional, Set, Union, Dict
from ...core.smtlib import (
    BitVec,
    Array,
    ConstraintSet,
)

from ape.api import Web3Provider


class ForkWorldState(Web3Provider):
    def __init__(self, underlay: Web3Provider):
        self._underlay: Web3Provider = underlay  # empty world state or forked world state
        self._deleted_accounts: Set[int] = set()
        # account state (EOA and contract)
        self._nonce: Dict[int, Union[int, BitVec]] = {}
        self._balance: Dict[int, Union[int, BitVec]] = {}
        self._storage: Dict[int, Storage] = {}
        self._code: Dict[int, Union[bytes, Array]] = {}
        # chain state
        self._blocknumber: Optional[Union[int, BitVec]] = None
        self._timestamp: Optional[Union[int, BitVec]] = None
        self._difficulty: Optional[Union[int, BitVec]] = None
        self._gaslimit: Optional[Union[int, BitVec]] = None
        self._coinbase: Optional[Union[int, BitVec]] = None

    def accounts(self) -> Set[int]:
        accounts: Set[int] = set()
        try:
            accounts = self._underlay.accounts()
        except NotImplementedError:
            pass
        return (
            accounts
            | self._nonce.keys()
            | self._balance.keys()
            | self._storage.keys()
            | self._code.keys()
        )

    def get_nonce(self, address: int) -> Union[int, BitVec]:
        if address in self._nonce:
            return self._nonce[address]
        else:
            return self._underlay.get_nonce(address)

    def get_balance(self, address: int) -> Union[int, BitVec]:
        if address in self._balance:
            return self._balance[address]
        else:
            return self._underlay.get_balance(address)

    def has_storage(self, address: int) -> bool:
        dirty = False
        try:
            dirty = self._underlay.has_storage(address)
        except NotImplementedError:
            pass
        storage = self._storage.get(address)
        if storage is not None:
            dirty = dirty or len(storage._data.written) > 0
        return dirty

    def get_storage(self, address: int) -> Optional[Storage]:
        storage = None
        try:
            storage = self._underlay.get_storage(address)
        except NotImplementedError:
            pass
        # sam.moelius: Rightfully, the overlay's storage should be merged into the underlay's
        # storage.  However, this is not currently implemented.
        if storage is not None:
            # sam.moelius: At present, the get_storage methods of both DefaultWorldState and
            # RemoteWorldState raise NotImplementedError.  So this exception should be unreachable.
            raise NotImplementedError("Merging of storage is not implemented")
        storage = self._storage.get(address)
        return storage

    def get_storage_data(self, address: int, offset: Union[int, BitVec]) -> Union[int, BitVec]:
        value: Union[int, BitVec] = 0
        # sam.moelius: If the account was ever deleted, then ignore the underlay's storage.
        if address not in self._deleted_accounts:
            try:
                value = self._underlay.get_storage_data(address, offset)
            except NotImplementedError:
                pass
        storage = self._storage.get(address)
        if storage is not None:
            value = storage.get(offset, value)
        return value

    def get_code(self, address: int) -> Union[bytes, Array]:
        if address in self._code:
            return self._code[address]
        else:
            return self._underlay.get_code(address)

    def get_blocknumber(self) -> Union[int, BitVec]:
        if self._blocknumber is not None:
            return self._blocknumber
        else:
            return self._underlay.get_blocknumber()

    def get_timestamp(self) -> Union[int, BitVec]:
        if self._timestamp is not None:
            return self._timestamp
        else:
            return self._underlay.get_timestamp()

    def get_difficulty(self) -> Union[int, BitVec]:
        if self._difficulty is not None:
            return self._difficulty
        else:
            return self._underlay.get_difficulty()

    def get_gaslimit(self) -> Union[int, BitVec]:
        if self._gaslimit is not None:
            return self._gaslimit
        else:
            return self._underlay.get_gaslimit()

    def get_coinbase(self) -> Union[int, BitVec]:
        if self._coinbase is not None:
            return self._coinbase
        else:
            return self._underlay.get_coinbase()

    def delete_account(self, address: int):
        # reset the account address's state to remote
        default_world_state = EmptyWorldState()
        self._nonce[address] = default_world_state.get_nonce(address)
        self._balance[address] = default_world_state.get_balance(address)
        self._storage[address] = Storage(address)
        self._code[address] = default_world_state.get_code(address)
        self._deleted_accounts.add(address)

    def set_nonce(self, address: int, value: Union[int, BitVec]):
        self._nonce[address] = value

    def set_balance(self, address: int, value: Union[int, BitVec]):
        self._balance[address] = value

    def set_storage(self, address: int, storage: Optional[Storage]):
        if storage is None:
            self._storage.pop(address, None)
        else:
            self._storage[address] = storage

    def set_storage_data(
        self,
        constraints: ConstraintSet,
        address: int,
        offset: Union[int, BitVec],
        value: Union[int, BitVec],
    ):
        storage = self._storage.get(address)
        if storage is None:
            storage = Storage(constraints, address)
            self._storage[address] = storage
        storage.set(offset, value)

    def set_code(self, address: int, code: Union[bytes, Array]):
        self._code[address] = code

    def set_blocknumber(self, value: Union[int, BitVec]):
        self._blocknumber = value

    def set_timestamp(self, value: Union[int, BitVec]):
        self._timestamp = value

    def set_difficulty(self, value: Union[int, BitVec]):
        self._difficulty = value

    def set_gaslimit(self, value: Union[int, BitVec]):
        self._gaslimit = value

    def set_coinbase(self, value: Union[int, BitVec]):
        self._coinbase = value
