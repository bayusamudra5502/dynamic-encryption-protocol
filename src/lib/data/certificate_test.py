from cryptography.x509.base import load_pem_x509_certificate
from lib.data.certificate import TLSCertificate

CERTIFICATE = """
-----BEGIN CERTIFICATE-----
MIICKzCCAdGgAwIBAgIUPU2eFllUkV3FBtjzLE1ribfXrqkwCgYIKoZIzj0EAwIw
azELMAkGA1UEBhMCSUQxEjAQBgNVBAgMCVdlc3QgSmF2YTEQMA4GA1UEBwwHQmFu
ZHVuZzEjMCEGA1UECgwaSW5zdGl0dXQgVGVrbm9sb2dpIEJhbmR1bmcxETAPBgNV
BAMMCENoYW9zVExTMB4XDTI0MDUwNzAxMjk1MVoXDTI1MDUwNzAxMjk1MVowazEL
MAkGA1UEBhMCSUQxEjAQBgNVBAgMCVdlc3QgSmF2YTEQMA4GA1UEBwwHQmFuZHVu
ZzEjMCEGA1UECgwaSW5zdGl0dXQgVGVrbm9sb2dpIEJhbmR1bmcxETAPBgNVBAMM
CENoYW9zVExTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENJkXSCTrqJoT+foc
Jgev+3X3pQUXvxe+hnRkwOAXeSZula2zm/tyir8xJpCrVSXx0q29w7L6DHUTLzuv
jUiMb6NTMFEwHQYDVR0OBBYEFKTZK1+HbsXVKirEwdYU5Yb2KnHJMB8GA1UdIwQY
MBaAFKTZK1+HbsXVKirEwdYU5Yb2KnHJMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZI
zj0EAwIDSAAwRQIhAKeQI9+tWKzz9Cmw934Cn5hQey35w0VXsdJfzEBOBJWhAiBW
ts1MsU2ljuBHyFbdzsAd4MLE+zgSXyYEwr2FZYIL/Q==
-----END CERTIFICATE-----
"""


def test_certificate():
    cert = load_pem_x509_certificate(CERTIFICATE.encode("utf-8"))
    certificate = TLSCertificate([cert])

    certificate_encoded = certificate.encode()
    certificate_new = TLSCertificate.parse(certificate_encoded)

    assert certificate == certificate_new
    assert certificate.get_certificates() == [cert]
