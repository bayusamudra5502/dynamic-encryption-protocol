from lib.data.common import TLSPayload


class Alert(TLSPayload):
    __alert_type: int
    __alert_description: int

    def __init__(self, alert_type: int, alert_description: int) -> None:
        self.__alert_type = alert_type
        self.__alert_description = alert_description

    def encode(self) -> bytes:
        return self.__alert_type.to_bytes(1, byteorder='big') + self.__alert_description.to_bytes(1, byteorder='big')

    @staticmethod
    def parse(data: bytes) -> 'TLSPayload':
        return Alert(data[0], data[1])

    def __eq__(self, other: 'Alert') -> bool:
        return self.__alert_type == other.__alert_type and self.__alert_description == other.__alert_description

    def length(self) -> int:
        return 2

    def get_alert_type(self) -> int:
        return self.__alert_type

    def get_alert_description(self) -> int:
        return self.__alert_description


class AlertLevel:
    WARNING = 1
    FATAL = 2


class AlertDescription:
    CLOSE_NOTIFY = 0
    UNEXPECTED_MESSAGE = 10
    BAD_RECORD_MAC = 20
    HANDSHAKE_FAILURE = 40
    NO_CERTIFICATE = 41
    BAD_CERTIFICATE = 42
    CERTIFICATE_REVOKED = 44
    CERTIFICATE_EXPIRED = 45
    CERTIFICATE_UNKNOWN = 46
    UNKNOWN_CA = 48
    DECODE_ERROR = 50
    DECRYPT_ERROR = 51
    EXPORT_RESTRICTION = 60
    PROTOCOL_VERSION = 70
    BAD_CERTIFICATE_STATUS_RESPONSE = 113
    BAD_CERTIFICATE_HASH_VALUE = 114
    CERTIFICATE_REQUIRED = 116
