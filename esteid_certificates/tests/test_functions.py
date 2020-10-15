import os
from unittest import TestCase

from esteid_certificates import (
    get_certificate_file_name,
    get_certificate,
    get_root_certificate,
    get_root_ca_file_name,
    ISSUER_CERTS,
    UnknownCertificateError,
)


class TestFunctions(TestCase):
    def test_get_certificate_file_name(self):
        for key, value in ISSUER_CERTS.items():
            path = get_certificate_file_name(key)
            self.assertEqual(os.path.basename(path), value)
            self.assertTrue(os.path.exists(path))

    def test_get_certificate(self):
        for key, value in ISSUER_CERTS.items():
            self.assertTrue(get_certificate(key).startswith(b'-----BEGIN CERTIFICATE-----'))

    def test_get_certificate_file_name__fails(self):
        with self.assertRaises(UnknownCertificateError):
            get_certificate_file_name("nonexistent")

    def test_get_certificate__fails(self):
        with self.assertRaises(UnknownCertificateError):
            get_certificate("nonexistent")

    def test_get_root_ca_file_name(self):
        path = get_root_ca_file_name()
        self.assertTrue(os.path.exists(path))

        for test in [False, True]:
            path = get_root_ca_file_name(test)
            self.assertTrue(os.path.exists(path))

    def test_get_root_certificate(self):
        cert = get_root_certificate()
        self.assertTrue(cert.startswith(b'-----BEGIN CERTIFICATE-----'))

        for test in [False, True]:
            cert = get_root_certificate(test)
            self.assertTrue(cert.startswith(b'-----BEGIN CERTIFICATE-----'))
