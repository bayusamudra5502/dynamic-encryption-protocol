from abc import ABC, abstractmethod
from lib.conn.tlsrecord import TLSApplicationRecordHandler, ContentType
from lib.conn.transport import Transport
from lib.data.common import ProtocolVersion
from lib.data.hello import ClientHello, Random, ServerHello, ServerHelloDone
from lib.data.layer import TLSRecordLayer
from lib.data.crypto import Signature, CipherSuite, CompressionMethod
from lib.data.exchange import ClientKeyExchange, ServerKeyExchange, ECDHParameter, ECPoint, ECParameter
from lib.data.handshake import Handshake, HandshakeType
from lib.data.certificate import TLSCertificate
from cryptography.x509 import Certificate
from lib.crypto.sign import sign, verify
from lib.data.cipherspec import ChangeCipherSpec
from lib.crypto.key import generate_master_secret, generate_shared_secret, generate_chaos_parameter
from lib.data.finish import Finished
from lib.crypto.key import generate_finished_payload
from lib.data.alert import Alert, AlertLevel, AlertDescription
from secrets import compare_digest
from secrets import randbits
from cryptography.x509 import Certificate as CryptographyCertificate


from cryptography.hazmat.primitives.asymmetric import ec


class TLSHandshake(ABC):
    _transport: Transport = None
    _version: ProtocolVersion = None

    def __init__(self, version: ProtocolVersion, transport: Transport) -> None:
        self._transport = transport
        self._version = version

    @abstractmethod
    def get_tls_application_record(self) -> TLSApplicationRecordHandler:
        pass

    @abstractmethod
    def run(self) -> None:
        pass

    def _get_handshake(self):
        while True:
            header = self._transport.recv(5)
            record = TLSRecordLayer.parse(header, with_data=False)

            if record.get_content_type() == ContentType.ALERT:
                data = self._transport.recv(record.get_content_size())
                alert_data = Alert.parse(data)

                if alert_data.get_alert_description() == AlertDescription.CLOSE_NOTIFY:
                    raise ConnectionAbortedError(
                        "Connection closed by peer")

                if alert_data.get_alert_type() == AlertLevel.FATAL:
                    raise ConnectionAbortedError(
                        "Connection closed because unexpected error happened")

                continue

            if record.get_content_type() == ContentType.CHANGE_CIPHER_SPEC:
                data = self._transport.recv(record.get_content_size())
                return ChangeCipherSpec.parse(data)

            if record.get_content_type() != ContentType.HANDSHAKE:
                self._transport.recv(record.get_content_size())
                continue

            data = self._transport.recv(record.get_content_size())
            return Handshake.parse(data)

    @abstractmethod
    def get_session_id(self) -> int:
        pass


class ClientHandshake(TLSHandshake):
    _client_hello = None
    _server_hello = None
    _server_key_exchange = None
    _server_certificate = None
    _server_hello_done = None
    _client_key_exchange = None
    _client_finished = None
    _server_finished = None

    _master_secret = None
    _change_cipher_spec = False

    _error_sent = False

    def __init__(self, version: ProtocolVersion,
                 transport: Transport,
                 server_certificate: list[CryptographyCertificate] = None, *,
                 # Testing purposes only
                 tls_client_hello: Handshake = None,
                 tls_server_hello: Handshake = None,
                 tls_server_key_exchange: Handshake = None,
                 tls_server_certificate: Handshake = None,
                 tls_server_hello_done: Handshake = None,
                 tls_client_key_exchange: Handshake = None,
                 tls_client_finished: Handshake = None,
                 tls_server_finished: Handshake = None,
                 handshake_phase=None
                 ) -> None:
        super().__init__(version, transport)

        self._phase = handshake_phase
        self._client_hello = tls_client_hello
        self._server_hello = tls_server_hello
        self._server_key_exchange = tls_server_key_exchange
        self._server_certificate = tls_server_certificate
        self._server_hello_done = tls_server_hello_done
        self._client_key_exchange = tls_client_key_exchange
        self._client_finished = tls_client_finished
        self._server_finished = tls_server_finished
        self._pinned_server_certificate = server_certificate

    class Phase:
        CLIENT_HELLO = 0
        SERVER_HELLO = 1
        KEY_EXCHANGE = 2
        FINISHED = 3
        ESTABLISHED = 4
        FAILED = -1

    def run(self) -> None:
        if self._phase is None:
            self._phase = ServerHandshake.Phase.CLIENT_HELLO

        while self._phase != ClientHandshake.Phase.ESTABLISHED:
            if self._phase == ClientHandshake.Phase.CLIENT_HELLO:
                self.client_hello()
            elif self._phase == ClientHandshake.Phase.SERVER_HELLO:
                self.server_hello()
            elif self._phase == ClientHandshake.Phase.KEY_EXCHANGE:
                self.key_exchange()
            elif self._phase == ClientHandshake.Phase.FINISHED:
                self.finished()
            elif self._phase == ClientHandshake.Phase.FAILED:
                if not self._error_sent:
                    data = TLSRecordLayer(
                        self._version,
                        ContentType.ALERT,
                        Alert(
                            alert_type=AlertLevel.FATAL,
                            alert_description=AlertDescription.HANDSHAKE_FAILURE
                        )
                    )
                    self._transport.send(data.encode())
                    self._error_sent = True

                raise Exception("Handshake failed")

    def client_hello(self) -> None:
        data = TLSRecordLayer(
            self._version,
            ContentType.HANDSHAKE,
            Handshake(
                HandshakeType.CLIENT_HELLO,
                ClientHello(
                    self._version,
                    Random(),
                    0,
                    [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CHAOS_SHA256],
                    [CompressionMethod.NULL],
                )
            )
        )

        self._client_hello = data.get_payload()
        self._transport.send(data.encode())
        self._phase = ClientHandshake.Phase.SERVER_HELLO

    def server_hello(self) -> None:
        data = None

        while self._server_hello_done is None or self._server_certificate is None:
            data = self._get_handshake()

            if data.get_type() == HandshakeType.SERVER_HELLO:
                self._server_hello = data
            elif data.get_type() == HandshakeType.SERVER_KEY_EXCHANGE:
                self._server_key_exchange = data
            elif data.get_type() == HandshakeType.SERVER_HELLO_DONE:
                self._server_hello_done = data
            elif data.get_type() == HandshakeType.CERTIFICATE:
                self._server_certificate = data

        # Verify Certificate
        if self._server_certificate is None:
            self._error_sent = True
            data = TLSRecordLayer(
                self._version,
                ContentType.ALERT,
                Alert(
                    alert_type=AlertLevel.FATAL,
                    alert_description=AlertDescription.NO_CERTIFICATE
                )
            )
            self._transport.send(data.encode())
            self._phase = ClientHandshake.Phase.FAILED
            raise Exception("Server Certificate is required")

        certificates = self._server_certificate.get_payload().get_certificates()
        if self._pinned_server_certificate != certificates:
            self._error_sent = True
            self._phase = ClientHandshake.Phase.FAILED
            data = TLSRecordLayer(
                self._version,
                ContentType.ALERT,
                Alert(
                    alert_type=AlertLevel.FATAL,
                    alert_description=AlertDescription.CERTIFICATE_UNKNOWN
                )
            )
            self._transport.send(data.encode())
            return

        try:
            if not self.__verify():
                # TODO: send alert
                self._phase = ClientHandshake.Phase.FAILED
                data = TLSRecordLayer(
                    self._version,
                    ContentType.ALERT,
                    Alert(
                        alert_type=AlertLevel.FATAL,
                        alert_description=AlertDescription.HANDSHAKE_FAILURE
                    )
                )
                self._transport.send(data.encode())
                return
        except Exception as e:
            self._phase = ClientHandshake.Phase.FAILED
            data = TLSRecordLayer(
                self._version,
                ContentType.ALERT,
                Alert(
                    alert_type=AlertLevel.FATAL,
                    alert_description=AlertDescription.BAD_CERTIFICATE
                )
            )
            self._transport.send(data.encode())
            raise e

        self._phase = ClientHandshake.Phase.KEY_EXCHANGE

    def key_exchange(self) -> None:
        self.__private = ec.generate_private_key(ec.SECP256R1())
        public = self.__private.public_key().public_numbers()
        point = ECPoint(public.x, public.y)

        client_exchange = TLSRecordLayer(
            self._version,
            ContentType.HANDSHAKE,
            Handshake(
                HandshakeType.CLIENT_KEY_EXCHANGE,
                ClientKeyExchange(point),
            )
        )

        self._client_key_exchange = client_exchange.get_payload()

        change_cipher_spec = TLSRecordLayer(
            self._version,
            ContentType.CHANGE_CIPHER_SPEC,
            ChangeCipherSpec(),
        )

        self.__generate_finished()

        client_finished = TLSRecordLayer(
            self._version,
            ContentType.HANDSHAKE,
            self._client_finished
        )

        self._transport.send(client_exchange.encode(
        ) + change_cipher_spec.encode() + client_finished.encode())

        self._phase = ClientHandshake.Phase.FINISHED

    def finished(self) -> None:
        while self._server_finished is None:
            data = self._get_handshake()

            if isinstance(data, ChangeCipherSpec):
                self._change_cipher_spec = True
            elif data.get_type() == HandshakeType.FINISHED:
                self._server_finished = data

        if not self.__validate_server_finished():
            data = TLSRecordLayer(
                self._version,
                ContentType.ALERT,
                Alert(
                    alert_type=AlertLevel.FATAL,
                    alert_description=AlertDescription.HANDSHAKE_FAILURE
                )
            )
            self._transport.send(data.encode())
            self._phase = ClientHandshake.Phase.FAILED
            raise Exception("Server Finished validation failed")

        self._phase = ClientHandshake.Phase.ESTABLISHED

    def __validate_server_finished(self) -> bool:
        if self._server_finished is None:
            return False

        handshake_messages = [self._client_hello, self._server_hello, self._server_key_exchange,
                              self._server_certificate, self._server_hello_done, self._client_key_exchange, self._client_finished]

        data = b""
        for message in handshake_messages:
            data += TLSRecordLayer(self._version,
                                   ContentType.HANDSHAKE, message).encode()

        return compare_digest(generate_finished_payload(self._master_secret, data, False), self._server_finished.get_payload().get_verify_data())

    def __generate_finished(self) -> None:
        premaster_key = generate_shared_secret(
            self._server_key_exchange.get_payload().get_params().get_public_key(), self.__private)

        client_hello: ClientHello = self._client_hello.get_payload()
        server_hello: ServerHello = self._server_hello.get_payload()
        self._master_secret = generate_master_secret(
            premaster_key, client_hello.get_random().get_bytes(), server_hello.get_random().get_bytes())

        handshake_messages = [self._client_hello, self._server_hello, self._server_key_exchange,
                              self._server_certificate, self._server_hello_done, self._client_key_exchange]

        data = b""
        for message in handshake_messages:
            data += TLSRecordLayer(self._version,
                                   ContentType.HANDSHAKE, message).encode()

        self._client_finished = Handshake(
            HandshakeType.FINISHED,
            Finished(generate_finished_payload(
                self._master_secret, data, True))
        )

    def __verify(self) -> None:
        tls_cert: TLSCertificate = self._server_certificate.get_payload()
        certificates = tls_cert.get_certificates()

        server_cert_pk = certificates[0].public_key()
        server_exchange: ServerKeyExchange = self._server_key_exchange.get_payload()

        return verify(server_exchange.get_params().encode(),
                      server_exchange.get_signature().get_signature(), server_cert_pk)

    def get_tls_application_record(self) -> TLSApplicationRecordHandler:
        if self._phase != ClientHandshake.Phase.ESTABLISHED:
            raise Exception("Handshake not finished")

        if self._change_cipher_spec == False:
            raise Exception("Change cipher spec not received")

        if self._master_secret is None:
            raise Exception("Master secret not generated")

        aes_client, aes_server, hmac_client, hmac_server = generate_chaos_parameter(
            self._master_secret, self._client_hello.get_payload().get_random().get_bytes(),
            self._server_hello.get_payload().get_random().get_bytes()
        )

        return TLSApplicationRecordHandler(self._version,  aes_client, aes_server, hmac_client, hmac_server)

    def get_session_id(self) -> int:
        return self._server_hello.get_payload().get_session_id()


class ServerHandshake(TLSHandshake):
    _client_hello = None
    _server_hello = None
    _server_key_exchange = None
    _server_certificate = None
    _server_hello_done = None
    _client_key_exchange = None
    _client_finished = None
    _server_finished = None

    _certificates = []
    _certificate_private_key = None
    _change_cipher_spec = False

    def __init__(self, version: ProtocolVersion, transport: Transport, server_certificate: list[Certificate], private_key: ec.EllipticCurvePrivateKey, *,
                 # Tesing purposes Only
                 tls_client_hello: Handshake = None,
                 tls_server_hello: Handshake = None,
                 tls_server_key_exchange: Handshake = None,
                 tls_server_certificate: Handshake = None,
                 tls_server_hello_done: Handshake = None,
                 tls_client_key_exchange: Handshake = None,
                 tls_client_finished: Handshake = None,
                 tls_server_finished: Handshake = None,
                 handshake_phase=None
                 ) -> None:
        super().__init__(version, transport)
        self._certificates = server_certificate

        if len(self._certificates) == 0:
            raise ValueError("should be at least 1 certificate")

        self._certificate_private_key = private_key

        self._phase = handshake_phase
        self._client_hello = tls_client_hello
        self._server_hello = tls_server_hello
        self._server_key_exchange = tls_server_key_exchange
        self._server_certificate = tls_server_certificate
        self._server_hello_done = tls_server_hello_done
        self._client_key_exchange = tls_client_key_exchange
        self._client_finished = tls_client_finished
        self._server_finished = tls_server_finished

    class Phase(ClientHandshake.Phase):
        pass

    def run(self) -> None:
        if self._phase is None:
            self._phase = ServerHandshake.Phase.CLIENT_HELLO

        while self._phase != ServerHandshake.Phase.ESTABLISHED:
            if self._phase == ServerHandshake.Phase.CLIENT_HELLO:
                self.client_hello()
            elif self._phase == ServerHandshake.Phase.SERVER_HELLO:
                self.server_hello()
            elif self._phase == ServerHandshake.Phase.KEY_EXCHANGE:
                self.key_exchange()
            elif self._phase == ServerHandshake.Phase.FINISHED:
                self.finished()
            elif self._phase == ServerHandshake.Phase.FAILED:
                data = TLSRecordLayer(
                    self._version,
                    ContentType.ALERT,
                    Alert(
                        alert_type=AlertLevel.FATAL,
                        alert_description=AlertDescription.HANDSHAKE_FAILURE
                    )
                )
                self._transport.send(data.encode())
                raise Exception("Handshake failed")

    def client_hello(self) -> None:
        client_hello = self._get_handshake()

        if client_hello.get_type() != HandshakeType.CLIENT_HELLO:
            return

        self._client_hello = client_hello
        self._phase = ClientHandshake.Phase.SERVER_HELLO

    def server_hello(self) -> None:
        server_hello = TLSRecordLayer(
            self._version,
            ContentType.HANDSHAKE,
            Handshake(
                HandshakeType.SERVER_HELLO,
                ServerHello(
                    self._version,
                    Random(),
                    randbits(32 * 8),
                    CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CHAOS_SHA256,
                    CompressionMethod.NULL,
                )
            )
        )

        self.__private = ec.generate_private_key(ec.SECP256R1())
        public = self.__private.public_key().public_numbers()
        point = ECPoint(public.x, public.y)
        param = ECDHParameter(
            ECParameter(),
            point,
        )
        signature = sign(param.encode(), self._certificate_private_key)

        server_key_exchange = TLSRecordLayer(
            self._version,
            ContentType.HANDSHAKE,
            Handshake(
                HandshakeType.SERVER_KEY_EXCHANGE,
                ServerKeyExchange(
                    param,
                    Signature(signature),  # TODO: Use real signature
                )
            )
        )

        server_hello_end = TLSRecordLayer(
            self._version,
            ContentType.HANDSHAKE,
            Handshake(
                HandshakeType.SERVER_HELLO_DONE,
                ServerHelloDone(),
            )
        )

        certificate = TLSRecordLayer(
            self._version,
            ContentType.HANDSHAKE,
            Handshake(
                HandshakeType.CERTIFICATE,
                TLSCertificate(self._certificates)
            )
        )

        # TODO: Send Certificate
        self._transport.send(server_hello.encode(
        ) + server_key_exchange.encode() + certificate.encode() + server_hello_end.encode())

        self._server_hello = server_hello.get_content()
        self._server_key_exchange = server_key_exchange.get_content()
        self._server_certificate = certificate.get_content()
        self._server_hello_done = server_hello_end.get_content()

        self._phase = ClientHandshake.Phase.KEY_EXCHANGE

    def key_exchange(self) -> None:
        while self._client_finished is None:
            data = self._get_handshake()

            if isinstance(data, ChangeCipherSpec):
                self._change_cipher_spec = True
            elif data.get_type() == HandshakeType.CLIENT_KEY_EXCHANGE:
                self._client_key_exchange = data
            elif data.get_type() == HandshakeType.FINISHED:
                self._client_finished = data

        if not self.__generate_finished_and_verify():
            data = TLSRecordLayer(
                self._version,
                ContentType.ALERT,
                Alert(
                    alert_type=AlertLevel.FATAL,
                    alert_description=AlertDescription.HANDSHAKE_FAILURE
                )
            )
            self._transport.send(data.encode())
            self._phase = ClientHandshake.Phase.FAILED
            raise Exception("Server Finished validation failed")

        self._phase = ClientHandshake.Phase.FINISHED

    def finished(self) -> None:
        change_cipher_spec = TLSRecordLayer(
            self._version,
            ContentType.CHANGE_CIPHER_SPEC,
            ChangeCipherSpec(),
        )

        server_finished = TLSRecordLayer(
            self._version,
            ContentType.HANDSHAKE,
            self._server_finished
        )

        self._transport.send(change_cipher_spec.encode() +
                             server_finished.encode())

        self._phase = ClientHandshake.Phase.ESTABLISHED

    def __generate_finished_and_verify(self) -> bool:
        premaster_key = generate_shared_secret(
            self._client_key_exchange.get_payload().get_public_key(), self.__private)

        client_hello: ClientHello = self._client_hello.get_payload()
        server_hello: ServerHello = self._server_hello.get_payload()
        self._master_secret = generate_master_secret(
            premaster_key, client_hello.get_random().get_bytes(), server_hello.get_random().get_bytes())

        client_message = [self._client_hello, self._server_hello, self._server_key_exchange,
                          self._server_certificate, self._server_hello_done, self._client_key_exchange]

        client_data = b""
        for message in client_message:
            client_data += TLSRecordLayer(self._version,
                                          ContentType.HANDSHAKE, message).encode()

        server_message = [self._client_hello, self._server_hello, self._server_key_exchange,
                          self._server_certificate, self._server_hello_done, self._client_key_exchange, self._client_finished]

        server_data = b""
        for message in server_message:
            server_data += TLSRecordLayer(self._version,
                                          ContentType.HANDSHAKE, message).encode()

        server_finished = Finished(
            generate_finished_payload(
                self._master_secret, server_data, False)
        )

        if not compare_digest(generate_finished_payload(self._master_secret, client_data, True), self._client_finished.get_payload().get_verify_data()):
            return False

        self._server_finished = Handshake(
            HandshakeType.FINISHED,
            server_finished
        )
        return True

    def get_tls_application_record(self) -> TLSApplicationRecordHandler:
        if self._phase != ClientHandshake.Phase.ESTABLISHED:
            raise Exception("Handshake not finished")

        if self._change_cipher_spec == False:
            raise Exception("Change cipher spec not received")

        if self._master_secret is None:
            raise Exception("Master secret not generated")

        aes_client, aes_server, hmac_client, hmac_server = generate_chaos_parameter(
            self._master_secret, self._client_hello.get_payload().get_random().get_bytes(),
            self._server_hello.get_payload().get_random().get_bytes()
        )

        return TLSApplicationRecordHandler(self._version, aes_server, aes_client, hmac_server, hmac_client)

    def get_session_id(self) -> int:
        return self._server_hello.get_payload().get_session_id()
