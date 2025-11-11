import typing as t
import pathlib
import warnings
from .constants import ISSUER_CERTS, ROOT_CA_FILES, TEST_ROOT_CA_FILES


__version__ = "1.0.4"


class UnknownCertificateError(Exception):
    pass


def get_certificate_file_path(issuer_name) -> pathlib.Path:
    try:
        base_name = ISSUER_CERTS[issuer_name]
    except KeyError:
        raise UnknownCertificateError(issuer_name)
    return base_name


def get_certificate_file_name(issuer_name) -> str:
    return str(get_certificate_file_path(issuer_name).resolve())


def get_certificate(issuer_name) -> bytes:
    file_path = get_certificate_file_path(issuer_name)
    with file_path.open('rb') as f:
        return f.read()


def get_root_ca_files(*, test=False) -> t.List[pathlib.Path]:
    return constants.TEST_ROOT_CA_FILES if test else constants.ROOT_CA_FILES


def get_root_certificates(*, test=False) -> t.List[bytes]:
    result = []
    for file_path in get_root_ca_files(test=test):
        with file_path.open("rb") as f:
            result.append(f.read())

    return result


def get_root_sk_ca_path(*, test=False) -> pathlib.Path:
    from .constants import constants_sk
    from .constants.constants import sk_directory

    file_name = constants_sk.TEST_ROOT_CA_FILE_NAME if test else constants_sk.ROOT_CA_FILE_NAME
    return sk_directory / file_name


def get_root_ca_file_name(test=False):
    warnings.warn(
        "There are multiple trust service providers now, and therefore multiple trust root CAs. "
        "`get_root_ca_file_name()` will only give you filename of SK solutions root CA. "
        "You likely need to update your code to use `get_root_ca_files()` instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    return str(get_root_sk_ca_path(test=test).resolve())


def get_root_certificate(test=False) -> bytes:
    warnings.warn(
        "There are multiple trust service providers now, and therefore multiple trust root CAs. "
        "`get_root_certificate()` will only give you filename of SK solutions root CA. "
        "You likely need to update your code to use `get_root_certificates()` instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    path = get_root_sk_ca_path(test=test)
    with path.open('rb') as f:
        return f.read()
