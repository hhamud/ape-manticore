from .storage import Storage
from typing import Optional, Set, Union, Dict, List
from ...core.smtlib import BitVec, Array, ConstraintSet, issymbolic
from .accountstate import AccountState
from .blockheaderstate import BlockHeaderState
from ape.api import ProviderAPI


class WorldState:
    def __init__(
        self,
        constraints: ConstraintSet,
        provider: Optional[ProviderAPI] = None,
    ) -> None:
        self.provider = provider
        self.constraints = constraints
        self.deleted_accounts: Set[int] = set()
        self.accounts_state: Dict[Union[int, BitVec], AccountState] = {}
        self.block_header_state: BlockHeaderState = BlockHeaderState(provider)

    def add_account(self, address: Union[int, BitVec]) -> Union[int, BitVec]:
        self.accounts_state[address] = AccountState(address, self.constraints)
        return address

    def accounts(self) -> List[Set[Union[int, BitVec]]]:
        return [set(self.accounts_state.keys())]

    def delete_account(self, address: int) -> Union[int, BitVec]:
        self.accounts_state.pop(address)
        self.deleted_accounts.add(address)
        return address
