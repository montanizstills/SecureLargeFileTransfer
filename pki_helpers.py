import subprocess
from datetime import datetime, timedelta
from socket import *
from time import sleep

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


# Generate a private key and save it to a file
def generate_private_key(filename: str, passphrase: str):
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )

    utf8_pass = passphrase.encode("utf-8")
    algorithm = serialization.BestAvailableEncryption(utf8_pass)

    with open(filename, "wb") as keyfile:
        keyfile.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=algorithm,
            )
        )

    return private_key


# Generate a public key from a private key
def generate_public_key(private_key, filename, **kwargs):
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, kwargs["country"]),
            x509.NameAttribute(
                NameOID.STATE_OR_PROVINCE_NAME, kwargs["state"]
            ),
            x509.NameAttribute(NameOID.LOCALITY_NAME, kwargs["locality"]),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, kwargs["org"]),
            x509.NameAttribute(NameOID.COMMON_NAME, kwargs["hostname"]),
        ]
    )

    # Because this is self signed, the issuer is always the subject
    issuer = subject

    # This certificate is valid from now until 30 days
    valid_from = datetime.utcnow()
    valid_to = valid_from + timedelta(days=30)

    # Used to build the certificate
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid_from)
        .not_valid_after(valid_to)
        .add_extension(x509.BasicConstraints(ca=True,
                                             path_length=None), critical=True)
    )

    # Sign the certificate with the private key
    public_key = builder.sign(
        private_key, hashes.SHA256(), default_backend()
    )

    with open(filename, "wb") as certfile:
        certfile.write(public_key.public_bytes(serialization.Encoding.PEM))

    return public_key


# Generate a Certificate Signing Request (CSR)
def generate_csr(private_key, filename, **kwargs):
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, kwargs["country"]),
            x509.NameAttribute(
                NameOID.STATE_OR_PROVINCE_NAME, kwargs["state"]
            ),
            x509.NameAttribute(NameOID.LOCALITY_NAME, kwargs["locality"]),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, kwargs["org"]),
            x509.NameAttribute(NameOID.COMMON_NAME, kwargs["hostname"]),
        ]
    )

    # Generate any alternative dns names
    alt_names = []
    for name in kwargs.get("alt_names", []):
        alt_names.append(x509.DNSName(name))
    san = x509.SubjectAlternativeName(alt_names)

    builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .add_extension(san, critical=False)
    )

    csr = builder.sign(private_key, hashes.SHA256(), default_backend())

    with open(filename, "wb") as csrfile:
        csrfile.write(csr.public_bytes(serialization.Encoding.PEM))

    return csr


# Sign a CSR with a CA
def sign_csr(csr, ca_public_key, ca_private_key, new_filename):
    valid_from = datetime.utcnow()
    valid_until = valid_from + timedelta(days=30)

    builder = (
        x509.CertificateBuilder()
        # base the subject name on the CSR, while the issuer is based on the Certificate Authority.
        .subject_name(csr.subject)
        .issuer_name(ca_public_key.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid_from)
        .not_valid_after(valid_until)
    )

    for extension in csr.extensions:
        builder = builder.add_extension(extension.value, extension.critical)

    public_key = builder.sign(
        private_key=ca_private_key,
        algorithm=hashes.SHA256(),
        backend=default_backend(),
    )

    with open(new_filename, "wb") as keyfile:
        keyfile.write(public_key.public_bytes(serialization.Encoding.PEM))


def do_aes_encryption(input_text, key):
    with open("aes_input.txt", "w") as f:
        f.write(input_text)

    ## encrypt input text via AES
    openssl_cmd = ["openssl", "enc", "-aes-256-cbc", "-k", key, "-in", "aes_input.txt", "-out", "aes-outfile.enc"]
    subprocess.run(openssl_cmd)
    # with open("aes-outfile.enc", "rb") as f:
    #     print(f.readlines())


def do_3des_decryption(input_file, key):
    ## decrypt input text via DES to a file called DES-decrypted.txt
    openssl_cmd = ["openssl", "enc", "-des3", "-d", "-in", input_file, "-out", "DES-decrypted.txt"]
    subprocess.run(openssl_cmd)
    # with open("3DES-decrypted.txt", "r") as f:
    #     print(f.readlines())


def send_file(src_fp, dst_ip, dst_port, encryption: bool):
    # send an encrypted file (source_fp) to a destination_fp using netcat or python equivalent, if encryption is True
    # otherwise, send unencrypted source_fp to destination_fp
    with create_connection((dst_ip, dst_port)) as conn:
        if encryption:
            do_aes_encryption(src_fp, "password")
        else:
            with open(src_fp) as file:
                msg = file.read()
                msg.encode('utf-8')
                conn.sendall(msg)


if __name__ == "__main__":
    private_key = generate_private_key("my_private_key.pem", "password")
    public_key = generate_public_key(
        private_key,
        "my_public_key.pem",
        country="US",
        state="CA",
        locality="San Francisco",
        org="My Company",
        hostname="example.com",
    )

    # In the real world, the CSR would be sent to an actual Certificate Authority like Verisign or Let’s Encrypt.
    csr = generate_csr(
        private_key,
        "my_csr.pem",
        country="US",
        state="CA",
        locality="San Francisco",
        org="My Company",
        hostname="example.com",
        alt_names=["example.net", "example.org"],
    )

    sign_csr(
        csr,
        public_key,
        private_key,
        "my_certificate.pem",
    )

    do_aes_encryption()
    send_file()  # encrypted - MontanizStills.txt
    send_file()  # unencrypted

    des3_decrypted = do_3des_decryption() #benard-key.txt
    # verify

