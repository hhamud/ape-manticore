from ape_manticore.manticore.platforms.state.provider import ProviderAPI
from .worldstate import EmptyWorldState
from .storage import Storage
from typing import Optional, Set, Union, Dict
from ...core.smtlib import BitVec, Array, ConstraintSet, issymbolic
from ape.api import ProviderAPI

# def isConnected(default_variable):
# def decorator(fn):
# def wrapper(self, *args, **kwargs):
# provider = getattr(self, 'provider', None)
# if provider is None:
# variable = getattr(self, default_variable)
# return fn(self, variable, *args, **kwargs)
# return wrapper
# return decorator


class AccountState:
    def __init__(self, provider: Optional[ProviderAPI]) -> None:
        self.provider = provider
        self.nonce: Union[int, BitVec] = 0
        self.balance: Union[int, BitVec] = 0
        self.storage: Union[Storage, Array] = Array()
        self.code: Union[bytes, Array] = bytes()

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

    def set_nonce(self, address: int, value: Union[int, BitVec]) -> None:
        self.nonce = value

    def set_balance(self, address: int, value: Union[int, BitVec]) -> None:
        self.balance = value

    def set_storage(self, address: int, storage: Optional[Storage]):
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

    def set_code(self, code: Union[bytes, Array]):
        self.code = code


class BlockHeaderState:
    def __init__(self, provider: Optional[ProviderAPI]) -> None:
        self.provider = provider
        # london hardfork values
        self.blocknumber: Union[int, BitVec] = 12965000
        self.timestamp: Union[int, BitVec] = 1628166822
        self.difficulty: Union[int, BitVec] = 7742494561645080
        self.gaslimit: Union[int, BitVec] = 30029122
        self.coinbase: Union[int, BitVec] = 0

    def get_blocknumber(self) -> Union[int, BitVec]:
        if self.provider is not None:
            self.provider.get_block()
        return self.blocknumber

    def get_timestamp(self) -> Union[int, BitVec]:
        if self.provider is not None:
            self.provider.get_timestamp()
        return self.timestamp

    def get_difficulty(self) -> Union[int, BitVec]:
        if self.provider is not None:
            self.provider.get_difficulty()
        return self.difficulty

    def get_gaslimit(self) -> Union[int, BitVec]:
        if self.provider is not None:
            self.provider.get_gaslimit()
        return self.gaslimit

    def get_coinbase(self) -> Union[int, BitVec]:
        if self.provider is not None:
            self.provider.get_coinbase()
        return self.coinbase

    def set_blocknumber(self, value: Union[int, BitVec]) -> None:
        self.blocknumber = value

    def set_timestamp(self, value: Union[int, BitVec]) -> None:
        self.timestamp = value

    def set_difficulty(self, value: Union[int, BitVec]) -> None:
        self.difficulty = value

    def set_gaslimit(self, value: Union[int, BitVec]) -> None:
        self.gaslimit = value

    def set_coinbase(self, value: Union[int, BitVec]) -> None:
        self.coinbase = value


class WorldState:
    def __init__(self, provider: Optional[ProviderAPI]) -> None:
        self.deleted_accounts: Set[int] = set()
        self.accounts: Dict[int, AccountState] = {}
        self.block_header_state: BlockHeaderState

    def accounts(self) -> Set[int]:
        pass

    def populate_state(self):
        pass

    def delete_account(self) -> Union[int, BitVec]:
        pass
