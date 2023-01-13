from typing import Dict, List, Optional, Tuple, Union
from ...core.smtlib import (
    BitVec,
    ConstraintSet,
)


class Storage:
    def __init__(
        self, constraints: ConstraintSet, address: int, items: Optional[Dict[int, int]] = None
    ):
        """
        :param constraints: the ConstraintSet with which this Storage object is associated
        :param address: the address that owns this storage
        :param items: optional items to populate the storage with
        """
        self._data = constraints.new_array(
            index_bits=256,
            value_bits=256,
            name=f"STORAGE_{address:x}",
            avoid_collisions=True,
            # sam.moelius: The use of default here creates unnecessary if-then-elses.  See
            # ArrayProxy.get in expression.py.
            # default=0,
        )
        if items is not None:
            for key, value in items.items():
                self.set(key, value)

    def __copy__(self):
        other = Storage.__new__(Storage)
        other._data = copy.copy(self._data)
        return other

    def __getitem__(self, offset: Union[int, BitVec]) -> Union[int, BitVec]:
        return self.get(offset, 0)

    def get(self, offset: Union[int, BitVec], default: Union[int, BitVec]) -> Union[int, BitVec]:
        return self._data.get(offset, default)

    def set(self, offset: Union[int, BitVec], value: Union[int, BitVec]):
        self._data[offset] = value

    def get_items(self) -> List[Tuple[Union[int, BitVec], Union[int, BitVec]]]:
        return self._data.get_items()

    def dump(self, stream: TextIOBase, state: State):
        concrete_indexes = set()
        for sindex in self._data.written:
            concrete_indexes.add(state.solve_one(sindex, constrain=True))

        for index in concrete_indexes:
            stream.write(
                f"storage[{index:x}] = {state.solve_one(self._data[index], constrain=True):x}\n"
            )
