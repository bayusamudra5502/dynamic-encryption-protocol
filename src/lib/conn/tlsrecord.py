from lib.data.common import *
from lib.data.layer import *
from lib.enc.aes import *

MODULO_SIZE = 2**64


class TLSRecordHandler:
    __version: ProtocolVersion = None
    __write_server_aes: Cipher = None
    __write_client_aes: Cipher = None
    __write_server_mac: MAC = None
    __write_client_mac: MAC = None
    __sequence_number: int

    def __init__(self,
                 version: ProtocolVersion,
                 write_enc: Cipher,
                 read_enc: Cipher,
                 write_mac: MAC,
                 read_mac: MAC,
                 *,
                 sequence_number=0) -> None:
        self.__version = version

        self.__write_server_aes = read_enc
        self.__write_client_aes = write_enc
        self.__write_server_mac = read_mac
        self.__write_client_mac = write_mac
        self.__sequence_number = sequence_number % MODULO_SIZE

    def parse(self, data: bytes) -> TLSRecordLayer:
        return TLSRecordLayer.parse(data)

    def unpack(self, record: TLSRecordLayer) -> bytes:
        data = record.get_content()

        sequence_number = self.__sequence_number

        mac_data = struct.pack(">Q", sequence_number) +\
            ContentType.APPLICATION_DATA +\
            self.__version.encode() +\
            struct.pack(">H", len(data)) +\
            data

        self.__write_server_mac.verify(mac_data, record.get_mac())
        self.__sequence_number = (sequence_number + 1) % MODULO_SIZE

        dec_data = self.__write_server_aes.decrypt(data)
        return dec_data

    def pack(self, data: bytes) -> TLSRecordLayer:
        enc_data = self.__write_client_aes.encrypt(data)
        sequence_number = self.__sequence_number

        mac = self.__write_client_mac.generate(
            struct.pack(">Q", sequence_number) +
            ContentType.APPLICATION_DATA +
            self.__version.encode() +
            struct.pack(">H", len(enc_data)) +
            enc_data
        )

        self.__sequence_number = (sequence_number + 1) % MODULO_SIZE

        return TLSRecordLayer(
            version=self.__version,
            content_type=ContentType.APPLICATION_DATA,
            content=enc_data,
            mac=mac
        )
