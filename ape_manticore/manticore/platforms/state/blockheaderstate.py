from ape_manticore.manticore.platforms.state.provider import ProviderAPI
from .worldstate import EmptyWorldState
from .storage import Storage
from typing import Optional, Set, Union, Dict, List
from ...core.smtlib import BitVec, Array, ConstraintSet, issymbolic
from ape.api import ProviderAPI


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
            return self.provider.get_block()
        return self.blocknumber

    def get_timestamp(self) -> Union[int, BitVec]:
        if self.provider is not None:
            return self.provider.get_timestamp()
        return self.timestamp

    def get_difficulty(self) -> Union[int, BitVec]:
        if self.provider is not None:
            return self.provider.get_difficulty()
        return self.difficulty

    def get_gaslimit(self) -> Union[int, BitVec]:
        if self.provider is not None:
            return self.provider.get_gaslimit()
        return self.gaslimit

    def get_coinbase(self) -> Union[int, BitVec]:
        if self.provider is not None:
            return self.provider.get_coinbase()
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
