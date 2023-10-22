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


# Error message representing "INVALID_FORMAT" type of the "error" message
# Since task 1 requires only these two, it is sufficient without impleneting the rest, will be changed ...
class InvalidFormatException(MessageException):
    NETWORK_ERROR_MESSAGE = "INVALID_FORMAT"

# Error message representing "INVALID_HANDSHAKE" type of the "error" message
# Since task 1 requires only these two, it is sufficient without impleneting the rest, will be changed ...
class InvalidHandshakeException(MessageException):
    NETWORK_ERROR_MESSAGE = "INVALID_HANDSHAKE"
