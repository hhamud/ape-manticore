"""
@generated by mypy-protobuf.  Do not edit manually!
isort:skip_file
"""
import builtins
import collections.abc
import google.protobuf.descriptor
import google.protobuf.internal.containers
import google.protobuf.internal.enum_type_wrapper
import google.protobuf.message
import sys
import typing

if sys.version_info >= (3, 10):
    import typing as typing_extensions
else:
    import typing_extensions

DESCRIPTOR: google.protobuf.descriptor.FileDescriptor

class ManticoreLogMessage(google.protobuf.message.Message):
    """LogMessage and StateList message types have "Manticore" in their names to distinguish them from those in mserialize"""

    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    CONTENT_FIELD_NUMBER: builtins.int
    content: builtins.str
    def __init__(
        self,
        *,
        content: builtins.str = ...,
    ) -> None: ...
    def ClearField(self, field_name: typing_extensions.Literal["content", b"content"]) -> None: ...

global___ManticoreLogMessage = ManticoreLogMessage

class ManticoreMessageList(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    MESSAGES_FIELD_NUMBER: builtins.int
    @property
    def messages(self) -> google.protobuf.internal.containers.RepeatedCompositeFieldContainer[global___ManticoreLogMessage]: ...
    def __init__(
        self,
        *,
        messages: collections.abc.Iterable[global___ManticoreLogMessage] | None = ...,
    ) -> None: ...
    def ClearField(self, field_name: typing_extensions.Literal["messages", b"messages"]) -> None: ...

global___ManticoreMessageList = ManticoreMessageList

class ManticoreState(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    STATE_ID_FIELD_NUMBER: builtins.int
    PC_FIELD_NUMBER: builtins.int
    PARENT_ID_FIELD_NUMBER: builtins.int
    CHILDREN_IDS_FIELD_NUMBER: builtins.int
    state_id: builtins.int
    pc: builtins.int
    parent_id: builtins.int
    @property
    def children_ids(self) -> google.protobuf.internal.containers.RepeatedScalarFieldContainer[builtins.int]: ...
    def __init__(
        self,
        *,
        state_id: builtins.int = ...,
        pc: builtins.int = ...,
        parent_id: builtins.int | None = ...,
        children_ids: collections.abc.Iterable[builtins.int] | None = ...,
    ) -> None: ...
    def HasField(self, field_name: typing_extensions.Literal["_parent_id", b"_parent_id", "parent_id", b"parent_id"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing_extensions.Literal["_parent_id", b"_parent_id", "children_ids", b"children_ids", "parent_id", b"parent_id", "pc", b"pc", "state_id", b"state_id"]) -> None: ...
    def WhichOneof(self, oneof_group: typing_extensions.Literal["_parent_id", b"_parent_id"]) -> typing_extensions.Literal["parent_id"] | None: ...

global___ManticoreState = ManticoreState

class ManticoreStateList(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    ACTIVE_STATES_FIELD_NUMBER: builtins.int
    WAITING_STATES_FIELD_NUMBER: builtins.int
    FORKED_STATES_FIELD_NUMBER: builtins.int
    ERRORED_STATES_FIELD_NUMBER: builtins.int
    COMPLETE_STATES_FIELD_NUMBER: builtins.int
    PAUSED_STATES_FIELD_NUMBER: builtins.int
    @property
    def active_states(self) -> google.protobuf.internal.containers.RepeatedCompositeFieldContainer[global___ManticoreState]:
        """state categories in Manticore - based on manticore enums StateStatus and StateList"""
    @property
    def waiting_states(self) -> google.protobuf.internal.containers.RepeatedCompositeFieldContainer[global___ManticoreState]: ...
    @property
    def forked_states(self) -> google.protobuf.internal.containers.RepeatedCompositeFieldContainer[global___ManticoreState]: ...
    @property
    def errored_states(self) -> google.protobuf.internal.containers.RepeatedCompositeFieldContainer[global___ManticoreState]: ...
    @property
    def complete_states(self) -> google.protobuf.internal.containers.RepeatedCompositeFieldContainer[global___ManticoreState]: ...
    @property
    def paused_states(self) -> google.protobuf.internal.containers.RepeatedCompositeFieldContainer[global___ManticoreState]: ...
    def __init__(
        self,
        *,
        active_states: collections.abc.Iterable[global___ManticoreState] | None = ...,
        waiting_states: collections.abc.Iterable[global___ManticoreState] | None = ...,
        forked_states: collections.abc.Iterable[global___ManticoreState] | None = ...,
        errored_states: collections.abc.Iterable[global___ManticoreState] | None = ...,
        complete_states: collections.abc.Iterable[global___ManticoreState] | None = ...,
        paused_states: collections.abc.Iterable[global___ManticoreState] | None = ...,
    ) -> None: ...
    def ClearField(self, field_name: typing_extensions.Literal["active_states", b"active_states", "complete_states", b"complete_states", "errored_states", b"errored_states", "forked_states", b"forked_states", "paused_states", b"paused_states", "waiting_states", b"waiting_states"]) -> None: ...

global___ManticoreStateList = ManticoreStateList

class ManticoreInstance(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    UUID_FIELD_NUMBER: builtins.int
    uuid: builtins.str
    def __init__(
        self,
        *,
        uuid: builtins.str = ...,
    ) -> None: ...
    def ClearField(self, field_name: typing_extensions.Literal["uuid", b"uuid"]) -> None: ...

global___ManticoreInstance = ManticoreInstance

class TerminateResponse(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    def __init__(
        self,
    ) -> None: ...

global___TerminateResponse = TerminateResponse

class Hook(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    class _HookType:
        ValueType = typing.NewType("ValueType", builtins.int)
        V: typing_extensions.TypeAlias = ValueType

    class _HookTypeEnumTypeWrapper(google.protobuf.internal.enum_type_wrapper._EnumTypeWrapper[Hook._HookType.ValueType], builtins.type):  # noqa: F821
        DESCRIPTOR: google.protobuf.descriptor.EnumDescriptor
        FIND: Hook._HookType.ValueType  # 0
        AVOID: Hook._HookType.ValueType  # 1
        CUSTOM: Hook._HookType.ValueType  # 2
        GLOBAL: Hook._HookType.ValueType  # 3

    class HookType(_HookType, metaclass=_HookTypeEnumTypeWrapper): ...
    FIND: Hook.HookType.ValueType  # 0
    AVOID: Hook.HookType.ValueType  # 1
    CUSTOM: Hook.HookType.ValueType  # 2
    GLOBAL: Hook.HookType.ValueType  # 3

    ADDRESS_FIELD_NUMBER: builtins.int
    TYPE_FIELD_NUMBER: builtins.int
    FUNC_TEXT_FIELD_NUMBER: builtins.int
    address: builtins.int
    type: global___Hook.HookType.ValueType
    func_text: builtins.str
    def __init__(
        self,
        *,
        address: builtins.int | None = ...,
        type: global___Hook.HookType.ValueType = ...,
        func_text: builtins.str | None = ...,
    ) -> None: ...
    def HasField(self, field_name: typing_extensions.Literal["_address", b"_address", "_func_text", b"_func_text", "address", b"address", "func_text", b"func_text"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing_extensions.Literal["_address", b"_address", "_func_text", b"_func_text", "address", b"address", "func_text", b"func_text", "type", b"type"]) -> None: ...
    @typing.overload
    def WhichOneof(self, oneof_group: typing_extensions.Literal["_address", b"_address"]) -> typing_extensions.Literal["address"] | None: ...
    @typing.overload
    def WhichOneof(self, oneof_group: typing_extensions.Literal["_func_text", b"_func_text"]) -> typing_extensions.Literal["func_text"] | None: ...

global___Hook = Hook

class NativeArguments(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    PROGRAM_PATH_FIELD_NUMBER: builtins.int
    BINARY_ARGS_FIELD_NUMBER: builtins.int
    ENVP_FIELD_NUMBER: builtins.int
    SYMBOLIC_FILES_FIELD_NUMBER: builtins.int
    CONCRETE_START_FIELD_NUMBER: builtins.int
    STDIN_SIZE_FIELD_NUMBER: builtins.int
    ADDITIONAL_MCORE_ARGS_FIELD_NUMBER: builtins.int
    HOOKS_FIELD_NUMBER: builtins.int
    EMULATE_UNTIL_FIELD_NUMBER: builtins.int
    program_path: builtins.str
    @property
    def binary_args(self) -> google.protobuf.internal.containers.RepeatedScalarFieldContainer[builtins.str]: ...
    @property
    def envp(self) -> google.protobuf.internal.containers.RepeatedScalarFieldContainer[builtins.str]: ...
    @property
    def symbolic_files(self) -> google.protobuf.internal.containers.RepeatedScalarFieldContainer[builtins.str]: ...
    concrete_start: builtins.str
    stdin_size: builtins.str
    additional_mcore_args: builtins.str
    @property
    def hooks(self) -> google.protobuf.internal.containers.RepeatedCompositeFieldContainer[global___Hook]: ...
    emulate_until: builtins.int
    def __init__(
        self,
        *,
        program_path: builtins.str = ...,
        binary_args: collections.abc.Iterable[builtins.str] | None = ...,
        envp: collections.abc.Iterable[builtins.str] | None = ...,
        symbolic_files: collections.abc.Iterable[builtins.str] | None = ...,
        concrete_start: builtins.str | None = ...,
        stdin_size: builtins.str | None = ...,
        additional_mcore_args: builtins.str | None = ...,
        hooks: collections.abc.Iterable[global___Hook] | None = ...,
        emulate_until: builtins.int | None = ...,
    ) -> None: ...
    def HasField(self, field_name: typing_extensions.Literal["_additional_mcore_args", b"_additional_mcore_args", "_concrete_start", b"_concrete_start", "_emulate_until", b"_emulate_until", "_stdin_size", b"_stdin_size", "additional_mcore_args", b"additional_mcore_args", "concrete_start", b"concrete_start", "emulate_until", b"emulate_until", "stdin_size", b"stdin_size"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing_extensions.Literal["_additional_mcore_args", b"_additional_mcore_args", "_concrete_start", b"_concrete_start", "_emulate_until", b"_emulate_until", "_stdin_size", b"_stdin_size", "additional_mcore_args", b"additional_mcore_args", "binary_args", b"binary_args", "concrete_start", b"concrete_start", "emulate_until", b"emulate_until", "envp", b"envp", "hooks", b"hooks", "program_path", b"program_path", "stdin_size", b"stdin_size", "symbolic_files", b"symbolic_files"]) -> None: ...
    @typing.overload
    def WhichOneof(self, oneof_group: typing_extensions.Literal["_additional_mcore_args", b"_additional_mcore_args"]) -> typing_extensions.Literal["additional_mcore_args"] | None: ...
    @typing.overload
    def WhichOneof(self, oneof_group: typing_extensions.Literal["_concrete_start", b"_concrete_start"]) -> typing_extensions.Literal["concrete_start"] | None: ...
    @typing.overload
    def WhichOneof(self, oneof_group: typing_extensions.Literal["_emulate_until", b"_emulate_until"]) -> typing_extensions.Literal["emulate_until"] | None: ...
    @typing.overload
    def WhichOneof(self, oneof_group: typing_extensions.Literal["_stdin_size", b"_stdin_size"]) -> typing_extensions.Literal["stdin_size"] | None: ...

global___NativeArguments = NativeArguments

class EVMArguments(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    CONTRACT_PATH_FIELD_NUMBER: builtins.int
    CONTRACT_NAME_FIELD_NUMBER: builtins.int
    SOLC_BIN_FIELD_NUMBER: builtins.int
    TX_LIMIT_FIELD_NUMBER: builtins.int
    TX_ACCOUNT_FIELD_NUMBER: builtins.int
    DETECTORS_TO_EXCLUDE_FIELD_NUMBER: builtins.int
    ADDITIONAL_FLAGS_FIELD_NUMBER: builtins.int
    contract_path: builtins.str
    contract_name: builtins.str
    solc_bin: builtins.str
    tx_limit: builtins.str
    tx_account: builtins.str
    @property
    def detectors_to_exclude(self) -> google.protobuf.internal.containers.RepeatedScalarFieldContainer[builtins.str]: ...
    additional_flags: builtins.str
    def __init__(
        self,
        *,
        contract_path: builtins.str = ...,
        contract_name: builtins.str = ...,
        solc_bin: builtins.str = ...,
        tx_limit: builtins.str | None = ...,
        tx_account: builtins.str | None = ...,
        detectors_to_exclude: collections.abc.Iterable[builtins.str] | None = ...,
        additional_flags: builtins.str | None = ...,
    ) -> None: ...
    def HasField(self, field_name: typing_extensions.Literal["_additional_flags", b"_additional_flags", "_tx_account", b"_tx_account", "_tx_limit", b"_tx_limit", "additional_flags", b"additional_flags", "tx_account", b"tx_account", "tx_limit", b"tx_limit"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing_extensions.Literal["_additional_flags", b"_additional_flags", "_tx_account", b"_tx_account", "_tx_limit", b"_tx_limit", "additional_flags", b"additional_flags", "contract_name", b"contract_name", "contract_path", b"contract_path", "detectors_to_exclude", b"detectors_to_exclude", "solc_bin", b"solc_bin", "tx_account", b"tx_account", "tx_limit", b"tx_limit"]) -> None: ...
    @typing.overload
    def WhichOneof(self, oneof_group: typing_extensions.Literal["_additional_flags", b"_additional_flags"]) -> typing_extensions.Literal["additional_flags"] | None: ...
    @typing.overload
    def WhichOneof(self, oneof_group: typing_extensions.Literal["_tx_account", b"_tx_account"]) -> typing_extensions.Literal["tx_account"] | None: ...
    @typing.overload
    def WhichOneof(self, oneof_group: typing_extensions.Literal["_tx_limit", b"_tx_limit"]) -> typing_extensions.Literal["tx_limit"] | None: ...

global___EVMArguments = EVMArguments

class ManticoreRunningStatus(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    IS_RUNNING_FIELD_NUMBER: builtins.int
    is_running: builtins.bool
    def __init__(
        self,
        *,
        is_running: builtins.bool = ...,
    ) -> None: ...
    def ClearField(self, field_name: typing_extensions.Literal["is_running", b"is_running"]) -> None: ...

global___ManticoreRunningStatus = ManticoreRunningStatus

class StopServerRequest(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    def __init__(
        self,
    ) -> None: ...

global___StopServerRequest = StopServerRequest

class StopServerResponse(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    def __init__(
        self,
    ) -> None: ...

global___StopServerResponse = StopServerResponse

class ControlStateRequest(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    class _StateAction:
        ValueType = typing.NewType("ValueType", builtins.int)
        V: typing_extensions.TypeAlias = ValueType

    class _StateActionEnumTypeWrapper(google.protobuf.internal.enum_type_wrapper._EnumTypeWrapper[ControlStateRequest._StateAction.ValueType], builtins.type):  # noqa: F821
        DESCRIPTOR: google.protobuf.descriptor.EnumDescriptor
        RESUME: ControlStateRequest._StateAction.ValueType  # 0
        PAUSE: ControlStateRequest._StateAction.ValueType  # 1
        KILL: ControlStateRequest._StateAction.ValueType  # 2

    class StateAction(_StateAction, metaclass=_StateActionEnumTypeWrapper): ...
    RESUME: ControlStateRequest.StateAction.ValueType  # 0
    PAUSE: ControlStateRequest.StateAction.ValueType  # 1
    KILL: ControlStateRequest.StateAction.ValueType  # 2

    STATE_ID_FIELD_NUMBER: builtins.int
    MANTICORE_INSTANCE_FIELD_NUMBER: builtins.int
    ACTION_FIELD_NUMBER: builtins.int
    state_id: builtins.int
    @property
    def manticore_instance(self) -> global___ManticoreInstance: ...
    action: global___ControlStateRequest.StateAction.ValueType
    def __init__(
        self,
        *,
        state_id: builtins.int = ...,
        manticore_instance: global___ManticoreInstance | None = ...,
        action: global___ControlStateRequest.StateAction.ValueType = ...,
    ) -> None: ...
    def HasField(self, field_name: typing_extensions.Literal["manticore_instance", b"manticore_instance"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing_extensions.Literal["action", b"action", "manticore_instance", b"manticore_instance", "state_id", b"state_id"]) -> None: ...

global___ControlStateRequest = ControlStateRequest

class ControlStateResponse(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    def __init__(
        self,
    ) -> None: ...

global___ControlStateResponse = ControlStateResponse
