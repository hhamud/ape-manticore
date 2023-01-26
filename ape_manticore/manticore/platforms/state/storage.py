from typing import Dict, List, Optional, Tuple, Union
from ...core.smtlib import (
    BitVec,
    ConstraintSet,
)
import copy
import copy
from io import TextIOBase
from typing import Dict, List, Optional, Tuple, Union
from ...ethereum.state import State


class Storage:
    def __init__(
        self,
        address: Union[int, BitVec],
        constraints: ConstraintSet,
        items: Optional[Dict[int, int]] = None,
    ):

        self.data = constraints.new_array(
            index_bits=256,
            value_bits=256,
            name=f"STORAGE_{address:x}",
            avoid_collisions=True,
        )

        # if storage is concrete, populate items into storage
        if items is not None:
            for key, value in items.items():
                self.set(key, value)

    def __copy__(self):
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

    def dump(self, stream: TextIOBase, state: State) -> TextIOBase:

        concrete_indexes = []
        if len(self.data.written) > 0:
            concrete_indexes = state.solve_one_n_batched(self.data.written, constrain=True)

        concrete_values = []
        if len(concrete_indexes) > 0:
            concrete_values = state.solve_one_n_batched(concrete_indexes, constrain=True)

        assert len(concrete_indexes) == len(concrete_values)
        for index, value in zip(concrete_indexes, concrete_values):
            stream.write(f"storage[{index:x}] = {value:x}\n")

        return stream
