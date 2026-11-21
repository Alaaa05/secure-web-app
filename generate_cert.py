# Task 4 - Creates a self-signed TLS certificate so the app can run over HTTPS.
#
# A real website gets its certificate from a Certificate Authority (e.g. Let's
# Encrypt). For a local project we sign our own, so the browser will show a
# warning the first time ("Your connection is not private"). The traffic is
# still encrypted with TLS; the warning only means no outside authority
# vouched for the certificate.
#
# Run:  python generate_cert.py      (app.py also runs it if the files are missing)

import datetime
import ipaddress

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import config


def generate(cert_file=config.CERT_FILE, key_file=config.KEY_FILE):
    # 2048-bit RSA key: the minimum size considered safe today
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)  # issuer = subject, that's what "self-signed" means
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        # the certificate is valid for these addresses only
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    with open(key_file, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"Created {cert_file} and {key_file}")


if __name__ == "__main__":
    generate()
