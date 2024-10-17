import os
from .constants import ISSUER_CERTS, ROOT_CA_FILE_NAME, TEST_ROOT_CA_FILE_NAME


__version__ = "1.0.2"

_dirname = os.path.dirname(__file__)
CERT_PATH = os.path.abspath(os.path.join(_dirname, 'files'))


class UnknownCertificateError(Exception):
    pass


def get_certificate_file_name(issuer_name):
    try:
        base_name = ISSUER_CERTS[issuer_name]
    except KeyError:
        raise UnknownCertificateError(issuer_name)
    return os.path.join(CERT_PATH, base_name)


def get_certificate(issuer_name):
    file_name = get_certificate_file_name(issuer_name)
    with open(file_name, 'rb') as f:
        return f.read()


def get_root_ca_file_name(test=False):
    file_name = TEST_ROOT_CA_FILE_NAME if test else ROOT_CA_FILE_NAME
    return os.path.join(CERT_PATH, file_name)


def get_root_certificate(test=False):
    path = get_root_ca_file_name(test=test)
    with open(path, 'rb') as f:
        return f.read()
