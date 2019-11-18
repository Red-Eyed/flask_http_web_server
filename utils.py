import random
import socket
import string
from pathlib import Path

import requests
from OpenSSL import crypto


def generate_password(strength):
    chars = string.ascii_letters
    passwd = "".join(random.choice(chars) for i in range(strength))
    return passwd


def get_local_ip():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]


def get_hostname():
    return socket.gethostname()


def get_global_ip():
    return requests.get('http://ip.42.pl/raw').text


def create_self_signed_cert(cert_file: Path, key_file: Path):
    if cert_file.exists() and key_file.exists():
        return
    else:
        try:
            cert_file.unlink()
            key_file.unlink()
        except FileNotFoundError:
            print("Generating cert files")

    # create a key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)

    # create a self-signed cert
    cert = crypto.X509()
    cert.set_version(2)
    cert.set_serial_number(random.randint(50000000, 100000000))
    cert.get_subject().CN = get_hostname()
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.set_pubkey(k)
    cert.sign(k, 'sha256')

    with open(str(cert_file), "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf8"))

    with open(str(key_file), "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf8"))
