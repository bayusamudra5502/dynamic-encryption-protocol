from lib.data.common import *
from lib.data.layer import *
from lib.crypto.aes import *
from lib.log import Log

MODULO_SIZE = 2**64


class TLSApplicationRecordHandler:
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

    def parse(self, data: bytes, *, with_data=True) -> TLSRecordLayer:
        return TLSRecordLayer.parse(data, with_data=with_data)

    def unpack(self, record: TLSRecordLayer) -> bytes:
        data = record.get_content().get_data()
        state_copy = self.__write_server_aes.copy()

        try:
            dec_data = self.__write_server_aes.decrypt(data)
        except ValueError as e:
            self.__write_server_aes = state_copy
            raise CipherException("Decryption failed: " + str(e))

        mac = dec_data[-MAC_SIZE:]
        payload = dec_data[:-MAC_SIZE]

        sequence_number = self.__sequence_number

        mac_data = struct.pack(">Q", sequence_number) +\
            ContentType.APPLICATION_DATA +\
            self.__version.encode() +\
            struct.pack(">H", len(payload)) +\
            payload

        try:
            self.__write_server_mac.verify(
                mac_data, mac)
        except CipherException as e:
            self.__write_server_aes = state_copy
            raise CipherException("MAC verification failed: " + str(e))

        self.__sequence_number = (sequence_number + 1) % MODULO_SIZE

        self.__write_server_mac.rotate()

        return payload

    def pack(self, data: bytes) -> TLSRecordLayer:
        sequence_number = self.__sequence_number
        mac_payload = struct.pack(">Q", sequence_number) + ContentType.APPLICATION_DATA + \
            self.__version.encode() + struct.pack(">H", len(data)) + data
        mac = self.__write_client_mac.generate(mac_payload)

        enc_data = self.__write_client_aes.encrypt(data + mac)

        self.__sequence_number = (sequence_number + 1) % MODULO_SIZE

        return TLSRecordLayer(
            version=self.__version,
            content_type=ContentType.APPLICATION_DATA,
            data=TLSCiphertext(enc_data),
        )

    def _get_params(self):
        return self.__version, self.__sequence_number, self.__write_server_aes, self.__write_client_aes, self.__write_server_mac, self.__write_client_mac
