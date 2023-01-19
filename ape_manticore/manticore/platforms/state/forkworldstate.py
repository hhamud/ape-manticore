from .storage import Storage
from typing import Optional, Set, Union, Dict, List
from ...core.smtlib import BitVec, Array, ConstraintSet, issymbolic
from .accountstate import AccountState
from .blockheaderstate import BlockHeaderState
from ape.api import ProviderAPI


class WorldState:
    def __init__(
        self,
        accounts: List[int],
        constraints: ConstraintSet,
        provider: Optional[ProviderAPI] = None,
    ) -> None:
        self.provider = provider
        self.constraints = constraints
        self.deleted_accounts: Set[int] = set()
        self.accounts_state: Dict[int, AccountState] = {}
        self.block_header_state: BlockHeaderState = BlockHeaderState(provider)

        # populate account state
        if self.provider is not None:
            for account in accounts:
                self.accounts_state[account] = AccountState(
                    account, self.constraints, self.provider
                )
        else:
            for account in accounts:
                self.accounts_state[account] = AccountState(account, self.constraints)

    def accounts(self) -> List[Set[int]]:
        return [set(self.accounts_state.keys())]

    def delete_account(self, address: int) -> Union[int, BitVec]:
        self.accounts_state.pop(address)
        self.deleted_accounts.add(address)
        return address
