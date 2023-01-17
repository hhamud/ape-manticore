from ape_manticore.manticore.platforms.state.provider import ProviderAPI
from .worldstate import EmptyWorldState
from .storage import Storage
from typing import Optional, Set, Union, Dict, List
from ...core.smtlib import BitVec, Array, ConstraintSet, issymbolic
from ape.api import ProviderAPI
from .accountstate import AccountState
from .blockheaderstate import BlockHeaderState


class BaseState:
    def __init__(self, provider: Optional[ProviderAPI]) -> None:
        self.provider = provider

    def isConnected(self) -> bool:
        return isinstance(self.provider, ProviderAPI)


class WorldState:
    def __init__(self, provider: Optional[ProviderAPI], accounts: List[int]) -> None:
        self.provider = provider
        self.deleted_accounts: Set[int] = set()
        self.accounts_state: Dict[int, AccountState] = {}
        self.block_header_state: BlockHeaderState = BlockHeaderState(provider)

        if self.provider is not None:
            self.populate_world(accounts)

    def populate_world(self, accounts: List[int]) -> None:
        world = AccountState(self.provider)
        for account in accounts:
            self.accounts_state[account] = {}
            self.accounts_state[account]["nonce"] = world.get_nonce(account)
            self.accounts_state[account]["code"] = world.get_code(account)
            self.accounts_state[account]["balance"] = world.get_balance(account)
            self.accounts_state[account]["storage"] = world.get_storage(account)

    def accounts(self) -> Set[int]:
        return set(self.accounts_state.keys())

    def delete_account(self, address: int) -> Union[int, BitVec]:
        self.accounts_state.pop(address)
        self.deleted_accounts.add(address)
        return address
