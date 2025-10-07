import pathlib
import typing as t
from . import constants_sk
from . import constants_zetes


TEST_CERTS: t.Dict[str, pathlib.Path] = {}
LIVE_CERTS: t.Dict[str, pathlib.Path] = {}


def register_certificate(
    registry: t.Dict[str, pathlib.Path],
    certificate_name: str,
    certificate_filename: str,
    subdirectory: pathlib.Path
):
    if certificate_name in registry:
        raise RuntimeError(
            f"Multiple certificates with the same name {certificate_name}, this is invalid configuration, "
            f"esteid-certificates package must be fixed."
        )
    registry[certificate_name] = subdirectory / certificate_filename


current_directory = pathlib.Path(__file__).parent
sk_directory = current_directory.parent / "files" / "sk"
zetes_directory = current_directory.parent / "files" / "zetes"


for name, filename in constants_sk.TEST_CERTS.items():
    register_certificate(TEST_CERTS, name, filename, sk_directory)
for name, filename in constants_sk.LIVE_CERTS.items():
    register_certificate(LIVE_CERTS, name, filename, sk_directory)

for name, filename in constants_zetes.TEST_CERTS.items():
    register_certificate(TEST_CERTS, name, filename, zetes_directory)
for name, filename in constants_zetes.LIVE_CERTS.items():
    register_certificate(LIVE_CERTS, name, filename, zetes_directory)


ISSUER_CERTS: t.Dict[str, pathlib.Path] = {**TEST_CERTS, **LIVE_CERTS}

ROOT_CA_FILES: t.List[pathlib.Path] = []
TEST_ROOT_CA_FILES: t.List[pathlib.Path] = []

for directory, filename in [
    (sk_directory, constants_sk.ROOT_CA_FILE_NAME),
    (zetes_directory, constants_zetes.ROOT_CA_FILE_NAME)
]:
    if filename is not None:
        ROOT_CA_FILES.append(directory / filename)

for directory, filename in [
    (sk_directory, constants_sk.TEST_ROOT_CA_FILE_NAME),
    (zetes_directory, constants_zetes.TEST_ROOT_CA_FILE_NAME)
]:
    if filename is not None:
        TEST_ROOT_CA_FILES.append(directory / filename)
