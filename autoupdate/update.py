import abc
import argparse
import dataclasses
import datetime
import enum
import logging
import os
import pathlib
import re
import subprocess
import urllib.parse
from functools import lru_cache

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_der_x509_certificate

import requests
import bs4
from ruff.__main__ import find_ruff_bin


class CertificateType(enum.Enum):
    INTERMEDIATE = enum.auto()
    ROOT = enum.auto()
    TEST = enum.auto()
    TEST_ROOT = enum.auto()


@dataclasses.dataclass
class Certificate:
    title: str
    link: str
    certificate_type: CertificateType

    @property
    def filename(self) -> str:
        filename = pathlib.Path(
            urllib.parse.unquote(urllib.parse.urlparse(self.link).path)
        ).name
        # Sometimes, certificates will have .prm.crt as a suffix, remove the crt/cer part
        while filename.endswith(".crt") or filename.endswith(".cer"):
            filename = filename[:-4]
        return filename

    def __str__(self) -> str:
        return f"{self.title} ({self.filename})"


class ZetesCertificate(Certificate):
    @property
    def filename(self) -> str:
        # Zetes certificates are always in DER format and always have had .crt extension so far
        # We re-encode them to PEM, so we need to change the extension as well to .pem
        # base implementation already deals with stripping out .cer or .crt if present
        return f"{super().filename}.pem"


class CertificateUpdater(abc.ABC):
    def __init__(self, dry_run=False):
        self.dry_run = dry_run
        self._certificates: list[Certificate] = []

    @property
    @abc.abstractmethod
    def directory(self) -> str:
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def constants_file(self) -> str:
        raise NotImplementedError()

    @classmethod
    def get_http_headers(cls) -> dict[str, str]:
        return {
            "User-Agent": "python-esteid-certificates updater; https://github.com/thorgate/esteid-certificates"
        }

    @lru_cache
    def get_document(self, url) -> bs4.BeautifulSoup:
        return bs4.BeautifulSoup(
            requests.get(
                url,
                headers=self.get_http_headers(),
            ).content,
            "html.parser",
        )

    @property
    def certificates(self) -> list[Certificate]:
        if self._certificates:
            return self._certificates

        self.load_all()
        self.check()
        return self._certificates

    @abc.abstractmethod
    def load_all(self):
        raise NotImplementedError()

    def get_certificate_by_type(self, certificate_type: CertificateType) -> list[Certificate]:
        return sorted(
            [
                cert
                for cert in self._certificates
                if cert.certificate_type == certificate_type
            ],
            key=lambda c: c.filename,
        )

    def check(self):
        if (
            n_root_certs := len(self.get_certificate_by_type(CertificateType.ROOT))
        ) != 1:
            logging.error(
                "Expected to find exactly one root certificate, found %s", n_root_certs
            )

        if (
            n_test_root_certs := len(
                self.get_certificate_by_type(CertificateType.TEST_ROOT)
            )
        ) != 1:
            logging.error(
                "Expected to find exactly one root certificate, found %s",
                n_test_root_certs,
            )

        if len(self.get_certificate_by_type(CertificateType.INTERMEDIATE)) < 1:
            logging.error(
                "Expected to find at least one intermediate certificate",
            )

        if len(self.get_certificate_by_type(CertificateType.TEST)) < 1:
            logging.error(
                "Expected to find at least one test certificate",
            )

    def update_directory(self, directory_path: str):
        full_path = pathlib.Path(directory_path) / self.directory
        existing_certificate_filenames = set(f.name for f in full_path.glob("*.pem"))
        updated_certificate_filenames = set(cert.filename for cert in self.certificates)
        removed_certificates = (
            existing_certificate_filenames - updated_certificate_filenames
        )
        added_certificates = (
            updated_certificate_filenames - existing_certificate_filenames
        )

        logging.info("%d certificates to be removed:", len(removed_certificates))
        for certificate in sorted(removed_certificates):
            logging.info(" * %s", certificate)

        root_certificate = self.get_certificate_by_type(CertificateType.ROOT)[0]

        logging.info(
            "Root certificate will be %s: %s",
            "created" if root_certificate.filename in added_certificates else "updated",
            root_certificate.filename,
        )

        test_root_certificate = self.get_certificate_by_type(CertificateType.TEST_ROOT)[
            0
        ]
        logging.info(
            "Test root certificate will be %s: %s",
            "created"
            if test_root_certificate.filename in added_certificates
            else "updated",
            test_root_certificate.filename,
        )

        intermediate_certificates = self.get_certificate_by_type(
            CertificateType.INTERMEDIATE
        )
        logging.info(
            "%d intermediate certificates to be updated:",
            len(intermediate_certificates),
        )
        for certificate in intermediate_certificates:
            logging.info(
                " %s %s",
                "+" if certificate.filename in added_certificates else "~",
                certificate,
            )

        test_certificates = self.get_certificate_by_type(CertificateType.TEST)
        logging.info("%d test certificates to be updated:", len(test_certificates))
        for certificate in test_certificates:
            logging.info(
                " %s %s",
                "+" if certificate.filename in added_certificates else "~",
                certificate,
            )

        if not self.dry_run:
            self._perform_update_directory(full_path, removed_certificates)

    def load_certificate(self, certificate: Certificate) -> bytes:
        return requests.get(certificate.link, headers=self.get_http_headers()).content

    def _perform_update_directory(
        self, full_path: pathlib.Path, removed_certificates: set[str]
    ):
        logging.info("Performing update")

        for certificate in self.certificates:
            logging.info("Updating certificate %s", certificate.filename)
            with (full_path / certificate.filename).open("wb") as f:
                f.write(self.load_certificate(certificate))

        for certificate in removed_certificates:
            logging.info("Removing certificate %s", certificate)
            (full_path / certificate).unlink()

    def update_constants(self, constants_path: str):
        full_path = pathlib.Path(constants_path) / self.constants_file
        logging.info("Updating constants file %s", full_path)

        test_certs = repr(
            {
                cert.title: cert.filename
                for cert in self.get_certificate_by_type(CertificateType.TEST)
            }
        )
        live_certs = repr(
            {
                cert.title: cert.filename
                for cert in self.get_certificate_by_type(CertificateType.INTERMEDIATE)
            }
        )
        root_certificate = repr(
            self.get_certificate_by_type(CertificateType.ROOT)[0].filename
        )
        test_root_certificate = repr(
            self.get_certificate_by_type(CertificateType.TEST_ROOT)[0].filename
        )
        with full_path.open("w") as f:
            f.write(
                f"# This file was autogenerated using update.py on {datetime.datetime.now()}\n\n"
                f"TEST_CERTS = {test_certs}\n"
                f"LIVE_CERTS = {live_certs}\n"
                f"ROOT_CA_FILE_NAME = {root_certificate}\n"
                f"TEST_ROOT_CA_FILE_NAME = {test_root_certificate}"
            )

        ruff = os.fsdecode(find_ruff_bin())
        subprocess.run([ruff, "format", str(full_path)])


class SKCertificateUpdater(CertificateUpdater):
    url = "https://www.skidsolutions.eu/resources/certificates/"
    directory = "sk"
    constants_file = "constants_sk.py"

    def load_all(self):
        self.load_root_certificates()
        self.load_intermediate_certificates()
        self.load_test_certificates()

    def load_intermediate_certificates(self):
        """Loads intermediate certificates from the page."""
        self._certificates = [
            certificate
            for certificate in self._certificates
            if certificate.certificate_type != CertificateType.INTERMEDIATE
        ]

        for certificate in self.load_certificates_from_tab(
            "nav-Intermediate-CAs", CertificateType.INTERMEDIATE
        ):
            self._certificates.append(certificate)

        for certificate in self.load_certificates_from_tab(
            "nav-TSA-certificates", CertificateType.INTERMEDIATE
        ):
            self._certificates.append(certificate)

    def load_test_certificates(self):
        """Loads test certificates from the page, expecting one of them to be Test Rood CA and the rest being
        intermediate test certificates."""

        # Clear previously loaded intermediate certificates
        self._certificates = [
            certificate
            for certificate in self._certificates
            if certificate.certificate_type
            not in [CertificateType.TEST, CertificateType.TEST_ROOT]
        ]

        for certificate in self.load_certificates_from_tab(
            "nav-Test-certificates", CertificateType.TEST
        ):
            if "Root CA" in certificate.title:
                certificate.certificate_type = CertificateType.TEST_ROOT
            if certificate.title.endswith(".sk.ee"):
                # Certificates for .sk.ee website: there will be multiple of those per hostname, and
                # we don't need those anyway
                continue
            self._certificates.append(certificate)

    def load_root_certificates(self):
        """Loads the single root certificate, which is expected to be EE Certification Centre Root CA, from the page."""
        # Clear previously loaded root certificates
        self._certificates = [
            certificate
            for certificate in self._certificates
            if certificate.certificate_type != CertificateType.ROOT
        ]

        for certificate in self.load_certificates_from_tab(
            "nav-Root-CAs", CertificateType.ROOT
        ):
            if "Root CA" not in certificate.title:
                continue
            self._certificates.append(certificate)

    def load_certificates_from_tab(
        self, tab_id: str, certificate_type: CertificateType
    ):
        cert_tab = self.get_document(self.url).find("div", {"id": tab_id})
        if cert_tab is None:
            logging.error("Could not find certificates tab #%s", tab_id)
            return

        certificates = cert_tab.find_all("div", {"class": "cert-item"})
        if not certificates:
            logging.error("No certificates found in tab #%s", tab_id)
            return

        logging.info("Found %s certificates in tab #%s", len(certificates), tab_id)
        for certificate in certificates:
            try:
                # Title is a text node followed by a span with additional info - to
                # get this text node, extract the first child and get the text
                certificate_title = next(
                    certificate.find("div", {"class": "title"}).children
                ).text.strip()
            except (StopIteration, AttributeError):
                logging.error("Could not get title for certificate %s", certificate)
                continue

            logging.debug("Found certificate %s", certificate_title)
            valid = certificate.find("p", string=re.compile(r"^(Valid|Valid\s/.*)$"))
            if not valid:
                logging.debug(
                    "Certificate %s is not valid, skipping", certificate_title
                )
                continue

            link = certificate.find("a", string="PEM")
            if not link:
                logging.error(
                    "Valid certificate %s has no download link we could use.",
                    certificate_title,
                )
                continue

            yield Certificate(
                title=certificate_title,
                link=link["href"],
                certificate_type=certificate_type,
            )


class ZetesCertificateUpdater(CertificateUpdater):
    directory = "zetes"
    constants_file = "constants_zetes.py"
    live_url = "https://repository.eidpki.ee/crt/"
    test_url = "https://www.id.ee/en/article/thales-id-card/"

    def load_all(self):
        self.load_live_certificates()
        self.load_test_certificates()

    def load_certificate(self, certificate: Certificate):
        content = super().load_certificate(certificate)
        parsed_certificate = load_der_x509_certificate(content)
        for component in parsed_certificate.subject:
            # While SK solutions kindly provide correct names on their webpage, Zetes doesn't
            # Correct title is important for certificate pinning we have in place, so we
            # extract it from the CN attribute, if we can.
            if component.oid == x509.oid.NameOID.COMMON_NAME:
                certificate.title = component.value
        return parsed_certificate.public_bytes(serialization.Encoding.PEM)

    def load_live_certificates(self):
        for anchor in self.get_document(self.live_url).find_all("a"):
            href = anchor.attrs.get("href")
            if href and href.lower().endswith("crt"):
                title = urllib.parse.unquote(
                    urllib.parse.urlparse(href).path.rsplit("/", 1)[-1]
                )
                root = "ca" in title.lower()
                self._certificates.append(
                    ZetesCertificate(
                        title=title,
                        link=href,
                        certificate_type=CertificateType.ROOT
                        if root
                        else CertificateType.INTERMEDIATE,
                    )
                )

    def load_test_certificates(self):
        visited = set()
        for anchor in self.get_document(self.test_url).find_all("a"):
            href = anchor.attrs.get("href")
            if href and href.lower().endswith("crt") and href not in visited:
                title = urllib.parse.unquote(
                    urllib.parse.urlparse(href).path.rsplit("/", 1)[-1]
                )
                root = "root" in anchor.parent.text.lower()
                self._certificates.append(
                    ZetesCertificate(
                        title=title,
                        link=href,
                        certificate_type=CertificateType.TEST_ROOT
                        if root
                        else CertificateType.TEST,
                    )
                )
                visited.add(href)


def main():
    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(
        description="Automatic updater for SK certificates"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Do not update anything, just list the certificates available for download.",
    )
    parser.add_argument(
        "directory",
        help="Directory with the certificates to update",
    )
    parser.add_argument(
        "--constants",
        default="",
        help="Path where to update constants file",
    )

    args = parser.parse_args()
    for updater_class in CertificateUpdater.__subclasses__():
        updater = updater_class(dry_run=args.dry_run)
        updater.update_directory(args.directory)
        if args.constants and not args.dry_run:
            updater.update_constants(args.constants)


if __name__ == "__main__":
    main()
