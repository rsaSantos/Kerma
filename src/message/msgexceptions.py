from abc import ABC, abstractproperty

"""
    Abstract class
"""

# Error messages
UNKNOWN_OBJECT_ERROR = "UNKNOWN_OBJECT"

class MessageException(ABC, Exception):
    def __init__(self, message, error_name) -> None:
        self.message = message
        self.error_name = error_name

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
    def __init__(self, message) -> None:
        self.message = message
        self.error_name = "INVALID_FORMAT"
        super().__init__(self.message, self.error_name)

class InvalidHandshakeException(MessageException):
    def __init__(self, message) -> None:
        self.message = message
        self.error_name = "INVALID_HANDSHAKE"
        super().__init__(self.message, self.error_name)

class InvalidTxConservationException(MessageException):
    def __init__(self, message) -> None:
        self.message = message
        self.error_name = "INVALID_TX_CONSERVATION"
        super().__init__(self.message, self.error_name)

class InvalidTxSignatureException(MessageException):
    def __init__(self, message) -> None:
        self.message = message
        self.error_name = "INVALID_TX_SIGNATURE"
        super().__init__(self.message, self.error_name)

class InvalidTxOutpointException(MessageException):
    def __init__(self, message) -> None:
        self.message = message
        self.error_name = "INVALID_TX_OUTPOINT"
        super().__init__(self.message, self.error_name)

class UnknownObjectException(MessageException):
    def __init__(self, message) -> None:
        self.message = message
        self.error_name = "UNKNOWN_OBJECT"
        super().__init__(self.message, self.error_name)
