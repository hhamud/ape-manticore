from typing import Dict, List, Optional, Tuple, Union
from ape_manticore.manticore.core.smtlib.expression import ArrayProxy
from ...core.smtlib import (
    BitVec,
    ConstraintSet,
)
import copy
import logging
import copy
from io import TextIOBase
from typing import Dict, List, Optional, Set, Tuple, Union, TypeVar
from ...ethereum.state import State


class Storage:
    def __init__(
        self, address: int, constraints: ConstraintSet, items: Optional[Dict[int, int]] = None
    ):

        self.data = constraints.new_array(
            index_bits=256,
            value_bits=256,
            name=f"STORAGE_{address:x}",
            avoid_collisions=True,
            # default=0,
        )

        # if storage is concrete, populate items into storage
        if items is not None:
            for key, value in items.items():
                self.set(key, value)

    def __copy__(self) -> Storage:
        other = Storage.__new__(Storage)
        other.data = copy.copy(self.data)
        return other

    def __getitem__(self, offset: Union[int, BitVec]) -> Union[int, BitVec]:
        return self.get(offset, 0)

    def get(self, offset: Union[int, BitVec], default: Union[int, BitVec]) -> Union[int, BitVec]:
        return self.data.get(offset, default)

    def set(self, offset: Union[int, BitVec], value: Union[int, BitVec]) -> None:
        self.data[offset] = value

    def get_items(self) -> List[Tuple[Union[int, BitVec], Union[int, BitVec]]]:
        return self.data.get_items()

    def dump(self, stream: TextIOBase, state: State) -> None:
        concrete_indexes = set()
        for sindex in self.data.written:
            concrete_indexes.add(state.solve_one(sindex, constrain=True))

        for index in concrete_indexes:
            stream.write(
                f"storage[{index:x}] = {state.solve_one(self.data[index], constrain=True):x}\n"
            )
