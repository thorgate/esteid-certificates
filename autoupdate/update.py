import argparse
import dataclasses
import datetime
import enum
import logging
import os
import pathlib
import subprocess
import urllib.parse
from functools import cached_property

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
    def filename(self):
        filename = pathlib.Path(
            urllib.parse.unquote(urllib.parse.urlparse(self.link).path)
        ).name
        while filename.endswith(".crt") or filename.endswith(".cer"):
            filename = filename[:-4]
        return filename

    def __str__(self):
        return f"{self.title} ({self.filename})"


class CertificateUpdater:
    def __init__(self, url: str, dry_run=False):
        self.url = url
        self.dry_run = dry_run
        self._certificates: list[Certificate] = []

    @cached_property
    def document(self):
        return bs4.BeautifulSoup(
            requests.get(
                self.url,
                headers={
                    "User-Agent": "python-esteid-certificates updater; https://github.com/thorgate/esteid-certificates",
                },
            ).content,
            "html.parser",
        )

    @property
    def certificates(self) -> list[Certificate]:
        if self._certificates:
            return self._certificates

        self.load_all()
        return self._certificates

    def load_all(self):
        self.load_root_certificates()
        self.load_intermediate_certificates()
        self.load_test_certificates()
        self.check()

    def check(self):
        if (
            not (
                n_root_certs := len(
                    [
                        cert
                        for cert in self._certificates
                        if cert.certificate_type == CertificateType.ROOT
                    ]
                )
            )
            == 1
        ):
            logging.error(
                "Expected to find exactly one root certificate, found %s", n_root_certs
            )

        if (
            not (
                n_test_root_certs := len(
                    [
                        cert
                        for cert in self._certificates
                        if cert.certificate_type == CertificateType.TEST_ROOT
                    ]
                )
            )
            == 1
        ):
            logging.error(
                "Expected to find exactly one root certificate, found %s",
                n_test_root_certs,
            )

        if (
            not (
                len(
                    [
                        cert
                        for cert in self._certificates
                        if cert.certificate_type == CertificateType.INTERMEDIATE
                    ]
                )
            )
            > 1
        ):
            logging.error(
                "Expected to find at least one intermediate certificate",
            )

        if (
            not (
                len(
                    [
                        cert
                        for cert in self._certificates
                        if cert.certificate_type == CertificateType.TEST
                    ]
                )
            )
            > 1
        ):
            logging.error(
                "Expected to find at least one test certificate",
            )

    def load_certificates_from_tab(
        self, tab_id: str, certificate_type: CertificateType
    ):
        cert_tab = self.document.find("div", {"id": tab_id})
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
                # Title is a text node that is followed by a span with additional info - to
                # get this text node extract first child and get the text
                certificate_title = next(
                    certificate.find("div", {"class": "title"}).children
                ).text.strip()
            except (StopIteration, AttributeError):
                logging.error("Could not get title for certificate %s", certificate)
                continue

            logging.debug("Found certificate %s", certificate_title)
            valid = certificate.find("p", string="Valid")
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

    def load_test_certificates(self):
        """Loads test certificates from the page, expecting one of them to be Test Rood CA and rest being
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
                # Certificates for .sk.ee website, there will be multiple of those per hostname and
                # we don't need those anyways
                continue
            self._certificates.append(certificate)

    def load_root_certificates(self):
        """Loads single root certificate, which is expected to be EE Certification Centre Root CA, from the page."""
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

    def update_directory(self, directory_path: str):
        existing_certificate_filenames = set(
            f.name for f in pathlib.Path(directory_path).glob("*.pem")
        )
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

        root_certificate = next(
            cert
            for cert in self.certificates
            if cert.certificate_type == CertificateType.ROOT
        )
        logging.info(
            "Root certificate will be %s: %s",
            "created" if root_certificate.filename in added_certificates else "updated",
            root_certificate.filename,
        )

        test_root_certificate = next(
            cert
            for cert in self.certificates
            if cert.certificate_type == CertificateType.TEST_ROOT
        )
        logging.info(
            "Test root certificate will be %s: %s",
            "created"
            if test_root_certificate.filename in added_certificates
            else "updated",
            test_root_certificate.filename,
        )

        intermediate_certificates = sorted(
            [
                cert
                for cert in self.certificates
                if cert.certificate_type == CertificateType.INTERMEDIATE
            ],
            key=lambda c: c.filename,
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

        test_certificates = sorted(
            [
                cert
                for cert in self.certificates
                if cert.certificate_type == CertificateType.TEST
            ],
            key=lambda c: c.filename,
        )
        logging.info("%d test certificates to be updated:", len(test_certificates))
        for certificate in test_certificates:
            logging.info(
                " %s %s",
                "+" if certificate.filename in added_certificates else "~",
                certificate,
            )

        if not self.dry_run:
            self._perform_update_directory(directory_path, removed_certificates)

    def _perform_update_directory(
        self, directory_path: str, removed_certificates: set[str]
    ):
        logging.info("Performing update")

        for certificate in self.certificates:
            logging.info("Updating certificate %s", certificate.filename)
            with (pathlib.Path(directory_path) / certificate.filename).open("wb") as f:
                f.write(requests.get(certificate.link).content)

        for certificate in removed_certificates:
            logging.info("Removing certificate %s", certificate)
            (pathlib.Path(directory_path) / certificate).unlink()

    def update_constants(self, constants_path: str):
        logging.info("Updating constants file %s", constants_path)

        test_certs = repr(
            {
                cert.title: cert.filename
                for cert in self.certificates
                if cert.certificate_type != CertificateType.TEST
            }
        )
        live_certs = repr(
            {
                cert.title: cert.filename
                for cert in self.certificates
                if cert.certificate_type != CertificateType.INTERMEDIATE
            }
        )
        issuer_certs = "{**TEST_CERTS, **LIVE_CERTS}"
        root_certificate = repr(
            next(
                cert
                for cert in self.certificates
                if cert.certificate_type == CertificateType.ROOT
            ).filename
        )

        test_root_certificate = repr(
            next(
                cert
                for cert in self.certificates
                if cert.certificate_type == CertificateType.TEST_ROOT
            ).filename
        )
        with (pathlib.Path(constants_path)).open("w") as f:
            f.write(
                f"# This file is autogenerated using update.py on {datetime.datetime.now()}\n\n"
                f"TEST_CERTS = {test_certs}\n"
                f"LIVE_CERTS = {live_certs}\n"
                f"ISSUER_CERTS = {issuer_certs}\n"
                f"ROOT_CA_FILE_NAME = {root_certificate}\n"
                f"TEST_ROOT_CA_FILE_NAME = {test_root_certificate}"
            )

        ruff = os.fsdecode(find_ruff_bin())
        subprocess.run([ruff, "format", constants_path])


def main():
    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(
        description="Automatic updater for SK certificates"
    )
    parser.add_argument(
        "--url",
        default="https://www.skidsolutions.eu/resources/certificates/",
        help="URL to get the certificates from",
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
        help="Path to constnats.py file to update",
    )

    args = parser.parse_args()
    updater = CertificateUpdater(args.url, dry_run=args.dry_run)
    updater.update_directory(args.directory)
    if args.constants and not args.dry_run:
        updater.update_constants(args.constants)


if __name__ == "__main__":
    main()
