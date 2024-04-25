from lib.data.common import *
from lib.data.layer import *
from lib.enc.aes import *

MODULO_SIZE = 2**64


class TLSRecordHandler:
    __version: ProtocolVersion = None
    __write_server_aes: DynamicAES = None
    __write_client_aes: DynamicAES = None
    __write_server_mac: DynamicHMAC = None
    __write_client_mac: DynamicHMAC = None
    __sequence_number: int

    def __init__(self,
                 version: ProtocolVersion,
                 write_enc_chaos: HenonMap,
                 read_enc_chaos: HenonMap,
                 write_mac_chaos: HenonMap,
                 read_mac_chaos: HenonMap,
                 *, sequence_number=0) -> None:
        self.__version = version

        self.__write_server_aes = DynamicAES(read_enc_chaos, block_size=16)
        self.__write_client_aes = DynamicAES(write_enc_chaos, block_size=16)
        self.__write_server_mac = DynamicHMAC(read_mac_chaos)
        self.__write_client_mac = DynamicHMAC(write_mac_chaos)
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
