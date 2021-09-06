# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: task_info.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from google.protobuf import timestamp_pb2 as google_dot_protobuf_dot_timestamp__pb2


DESCRIPTOR = _descriptor.FileDescriptor(
  name='task_info.proto',
  package='pai.pouw.task_info',
  syntax='proto3',
  serialized_options=None,
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\x0ftask_info.proto\x12\x12pai.pouw.task_info\x1a\x1fgoogle/protobuf/timestamp.proto\"1\n\x0fTaskListRequest\x12\x0c\n\x04page\x18\x01 \x01(\r\x12\x10\n\x08per_page\x18\x02 \x01(\r\"\x97\x01\n\nTaskRecord\x12\x0f\n\x07task_id\x18\x01 \x01(\t\x12\x12\n\nmodel_type\x18\x02 \x01(\t\x12\x10\n\x08nodes_no\x18\x03 \x01(\x04\x12\x12\n\nbatch_size\x18\x04 \x01(\r\x12\x11\n\toptimizer\x18\x05 \x01(\t\x12+\n\x07\x63reated\x18\x06 \x01(\x0b\x32\x1a.google.protobuf.Timestamp\"\xed\x01\n\nPagination\x12\x0c\n\x04page\x18\x01 \x01(\r\x12\x10\n\x08per_page\x18\x02 \x01(\r\x12\x12\n\npage_count\x18\x03 \x01(\r\x12\x13\n\x0btotal_count\x18\x04 \x01(\r\x12=\n\nnavigation\x18\x05 \x01(\x0b\x32).pai.pouw.task_info.Pagination.Navigation\x1aW\n\nNavigation\x12\x0c\n\x04self\x18\x01 \x01(\t\x12\r\n\x05\x66irst\x18\x02 \x01(\t\x12\x10\n\x08previous\x18\x03 \x01(\t\x12\x0c\n\x04next\x18\x04 \x01(\t\x12\x0c\n\x04last\x18\x05 \x01(\t\"\xa7\x01\n\x10TaskListResponse\x12\x30\n\x04\x63ode\x18\x01 \x01(\x0e\x32\".pai.pouw.task_info.HTTPReturnCode\x12\x32\n\npagination\x18\x02 \x01(\x0b\x32\x1e.pai.pouw.task_info.Pagination\x12-\n\x05tasks\x18\x03 \x03(\x0b\x32\x1e.pai.pouw.task_info.TaskRecord*\\\n\x0eHTTPReturnCode\x12\x11\n\rGENERAL_ERROR\x10\x00\x12\x07\n\x02OK\x10\xc8\x01\x12\x10\n\x0b\x42\x41\x44_REQUEST\x10\x90\x03\x12\x0e\n\tNOT_FOUND\x10\x94\x03\x12\x0c\n\x07INVALID\x10\xa6\x03\x32\xa6\x02\n\x08TaskInfo\x12\\\n\x0fGetWaitingTasks\x12#.pai.pouw.task_info.TaskListRequest\x1a$.pai.pouw.task_info.TaskListResponse\x12\\\n\x0fGetStartedTasks\x12#.pai.pouw.task_info.TaskListRequest\x1a$.pai.pouw.task_info.TaskListResponse\x12^\n\x11GetCompletedTasks\x12#.pai.pouw.task_info.TaskListRequest\x1a$.pai.pouw.task_info.TaskListResponseb\x06proto3'
  ,
  dependencies=[google_dot_protobuf_dot_timestamp__pb2.DESCRIPTOR,])

_HTTPRETURNCODE = _descriptor.EnumDescriptor(
  name='HTTPReturnCode',
  full_name='pai.pouw.task_info.HTTPReturnCode',
  filename=None,
  file=DESCRIPTOR,
  create_key=_descriptor._internal_create_key,
  values=[
    _descriptor.EnumValueDescriptor(
      name='GENERAL_ERROR', index=0, number=0,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='OK', index=1, number=200,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='BAD_REQUEST', index=2, number=400,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='NOT_FOUND', index=3, number=404,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='INVALID', index=4, number=422,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=687,
  serialized_end=779,
)
_sym_db.RegisterEnumDescriptor(_HTTPRETURNCODE)

HTTPReturnCode = enum_type_wrapper.EnumTypeWrapper(_HTTPRETURNCODE)
GENERAL_ERROR = 0
OK = 200
BAD_REQUEST = 400
NOT_FOUND = 404
INVALID = 422



_TASKLISTREQUEST = _descriptor.Descriptor(
  name='TaskListRequest',
  full_name='pai.pouw.task_info.TaskListRequest',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='page', full_name='pai.pouw.task_info.TaskListRequest.page', index=0,
      number=1, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='per_page', full_name='pai.pouw.task_info.TaskListRequest.per_page', index=1,
      number=2, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=72,
  serialized_end=121,
)


_TASKRECORD = _descriptor.Descriptor(
  name='TaskRecord',
  full_name='pai.pouw.task_info.TaskRecord',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='task_id', full_name='pai.pouw.task_info.TaskRecord.task_id', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='model_type', full_name='pai.pouw.task_info.TaskRecord.model_type', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='nodes_no', full_name='pai.pouw.task_info.TaskRecord.nodes_no', index=2,
      number=3, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='batch_size', full_name='pai.pouw.task_info.TaskRecord.batch_size', index=3,
      number=4, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='optimizer', full_name='pai.pouw.task_info.TaskRecord.optimizer', index=4,
      number=5, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='created', full_name='pai.pouw.task_info.TaskRecord.created', index=5,
      number=6, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=124,
  serialized_end=275,
)


_PAGINATION_NAVIGATION = _descriptor.Descriptor(
  name='Navigation',
  full_name='pai.pouw.task_info.Pagination.Navigation',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='self', full_name='pai.pouw.task_info.Pagination.Navigation.self', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='first', full_name='pai.pouw.task_info.Pagination.Navigation.first', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='previous', full_name='pai.pouw.task_info.Pagination.Navigation.previous', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='next', full_name='pai.pouw.task_info.Pagination.Navigation.next', index=3,
      number=4, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='last', full_name='pai.pouw.task_info.Pagination.Navigation.last', index=4,
      number=5, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=428,
  serialized_end=515,
)

_PAGINATION = _descriptor.Descriptor(
  name='Pagination',
  full_name='pai.pouw.task_info.Pagination',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='page', full_name='pai.pouw.task_info.Pagination.page', index=0,
      number=1, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='per_page', full_name='pai.pouw.task_info.Pagination.per_page', index=1,
      number=2, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='page_count', full_name='pai.pouw.task_info.Pagination.page_count', index=2,
      number=3, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='total_count', full_name='pai.pouw.task_info.Pagination.total_count', index=3,
      number=4, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='navigation', full_name='pai.pouw.task_info.Pagination.navigation', index=4,
      number=5, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[_PAGINATION_NAVIGATION, ],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=278,
  serialized_end=515,
)


_TASKLISTRESPONSE = _descriptor.Descriptor(
  name='TaskListResponse',
  full_name='pai.pouw.task_info.TaskListResponse',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='code', full_name='pai.pouw.task_info.TaskListResponse.code', index=0,
      number=1, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='pagination', full_name='pai.pouw.task_info.TaskListResponse.pagination', index=1,
      number=2, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='tasks', full_name='pai.pouw.task_info.TaskListResponse.tasks', index=2,
      number=3, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=518,
  serialized_end=685,
)

_TASKRECORD.fields_by_name['created'].message_type = google_dot_protobuf_dot_timestamp__pb2._TIMESTAMP
_PAGINATION_NAVIGATION.containing_type = _PAGINATION
_PAGINATION.fields_by_name['navigation'].message_type = _PAGINATION_NAVIGATION
_TASKLISTRESPONSE.fields_by_name['code'].enum_type = _HTTPRETURNCODE
_TASKLISTRESPONSE.fields_by_name['pagination'].message_type = _PAGINATION
_TASKLISTRESPONSE.fields_by_name['tasks'].message_type = _TASKRECORD
DESCRIPTOR.message_types_by_name['TaskListRequest'] = _TASKLISTREQUEST
DESCRIPTOR.message_types_by_name['TaskRecord'] = _TASKRECORD
DESCRIPTOR.message_types_by_name['Pagination'] = _PAGINATION
DESCRIPTOR.message_types_by_name['TaskListResponse'] = _TASKLISTRESPONSE
DESCRIPTOR.enum_types_by_name['HTTPReturnCode'] = _HTTPRETURNCODE
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

TaskListRequest = _reflection.GeneratedProtocolMessageType('TaskListRequest', (_message.Message,), {
  'DESCRIPTOR' : _TASKLISTREQUEST,
  '__module__' : 'task_info_pb2'
  # @@protoc_insertion_point(class_scope:pai.pouw.task_info.TaskListRequest)
  })
_sym_db.RegisterMessage(TaskListRequest)

TaskRecord = _reflection.GeneratedProtocolMessageType('TaskRecord', (_message.Message,), {
  'DESCRIPTOR' : _TASKRECORD,
  '__module__' : 'task_info_pb2'
  # @@protoc_insertion_point(class_scope:pai.pouw.task_info.TaskRecord)
  })
_sym_db.RegisterMessage(TaskRecord)

Pagination = _reflection.GeneratedProtocolMessageType('Pagination', (_message.Message,), {

  'Navigation' : _reflection.GeneratedProtocolMessageType('Navigation', (_message.Message,), {
    'DESCRIPTOR' : _PAGINATION_NAVIGATION,
    '__module__' : 'task_info_pb2'
    # @@protoc_insertion_point(class_scope:pai.pouw.task_info.Pagination.Navigation)
    })
  ,
  'DESCRIPTOR' : _PAGINATION,
  '__module__' : 'task_info_pb2'
  # @@protoc_insertion_point(class_scope:pai.pouw.task_info.Pagination)
  })
_sym_db.RegisterMessage(Pagination)
_sym_db.RegisterMessage(Pagination.Navigation)

TaskListResponse = _reflection.GeneratedProtocolMessageType('TaskListResponse', (_message.Message,), {
  'DESCRIPTOR' : _TASKLISTRESPONSE,
  '__module__' : 'task_info_pb2'
  # @@protoc_insertion_point(class_scope:pai.pouw.task_info.TaskListResponse)
  })
_sym_db.RegisterMessage(TaskListResponse)



_TASKINFO = _descriptor.ServiceDescriptor(
  name='TaskInfo',
  full_name='pai.pouw.task_info.TaskInfo',
  file=DESCRIPTOR,
  index=0,
  serialized_options=None,
  create_key=_descriptor._internal_create_key,
  serialized_start=782,
  serialized_end=1076,
  methods=[
  _descriptor.MethodDescriptor(
    name='GetWaitingTasks',
    full_name='pai.pouw.task_info.TaskInfo.GetWaitingTasks',
    index=0,
    containing_service=None,
    input_type=_TASKLISTREQUEST,
    output_type=_TASKLISTRESPONSE,
    serialized_options=None,
    create_key=_descriptor._internal_create_key,
  ),
  _descriptor.MethodDescriptor(
    name='GetStartedTasks',
    full_name='pai.pouw.task_info.TaskInfo.GetStartedTasks',
    index=1,
    containing_service=None,
    input_type=_TASKLISTREQUEST,
    output_type=_TASKLISTRESPONSE,
    serialized_options=None,
    create_key=_descriptor._internal_create_key,
  ),
  _descriptor.MethodDescriptor(
    name='GetCompletedTasks',
    full_name='pai.pouw.task_info.TaskInfo.GetCompletedTasks',
    index=2,
    containing_service=None,
    input_type=_TASKLISTREQUEST,
    output_type=_TASKLISTRESPONSE,
    serialized_options=None,
    create_key=_descriptor._internal_create_key,
  ),
])
_sym_db.RegisterServiceDescriptor(_TASKINFO)

DESCRIPTOR.services_by_name['TaskInfo'] = _TASKINFO

# @@protoc_insertion_point(module_scope)
