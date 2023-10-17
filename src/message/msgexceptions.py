from abc import ABC, abstractproperty

"""
    Abstract class
"""
class MessageException(ABC, Exception):
    NETWORK_ERROR_MESSAGE = ""


class MsgParseException(MessageException):
    NETWORK_ERROR_MESSAGE = "Invalid message received"


class MalformedMsgException(MessageException):
    NETWORK_ERROR_MESSAGE = "Malformed message received"


class UnsupportedMsgException(MessageException):
    NETWORK_ERROR_MESSAGE = "Unsupported message received"


class UnexpectedMsgException(MessageException):
    NETWORK_ERROR_MESSAGE = "Unexpected message received"
