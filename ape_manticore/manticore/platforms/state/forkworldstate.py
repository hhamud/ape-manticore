from .storage import Storage
from typing import Optional, Set, Union, Dict, List
from ...core.smtlib import BitVec, ConstraintSet
from .accountstate import AccountState
from .blockheaderstate import BlockHeaderState
from ape.api import ProviderAPI


class WorldState:
    def __init__(
        self,
        constraints: ConstraintSet,
        provider: Optional[ProviderAPI] = None,
    ) -> None:
        self.provider: Optional[ProviderAPI] = provider
        self.constraints: ConstraintSet = constraints
        self.deleted_accounts: Set[int] = set()
        self.accounts_state: Dict[int, AccountState] = {}
        self.block_header_state: BlockHeaderState = BlockHeaderState(provider)

    def add_account(
        self,
        address: int,
        balance: int,
        nonce: Optional[int],
        storage: Optional[Storage],
        code: Optional[bytes],
    ) -> Union[int, BitVec]:
        self.accounts_state[address] = AccountState(
            address, self.constraints, balance, nonce, storage, code, self.provider
        )
        return address

    def accounts(self) -> List[int]:
        return list(self.accounts_state.keys())

    def delete_account(self, address: int) -> Union[int, BitVec]:
        if address in self.accounts_state:
            self.accounts_state.pop(address)
            self.deleted_accounts.add(address)
        return address
