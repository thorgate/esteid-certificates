import os

__version__ = "1.0.1"

_dirname = os.path.dirname(__file__)
CERT_PATH = os.path.abspath(os.path.join(_dirname, 'files'))

ISSUER_CERTS = {
    # Test certs
    'TEST of ESTEID2018': 'TEST_of_ESTEID2018.pem',
    'TEST of SK OCSP RESPONDER 2011': 'TEST_of_SK_OCSP_RESPONDER_2011.pem',
    'TEST of EID-SK 2011': 'TEST_of_EID-SK_2011.pem',
    'TEST of EID-SK 2016': 'TEST_of_EID-SK_2016.pem',
    'TEST of ESTEID-SK 2011': 'TEST_of_ESTEID-SK_2011.pem',
    'TEST of ESTEID-SK 2015': 'TEST_of_ESTEID-SK_2015.pem',
    'TEST of KLASS3-SK 2010': 'TEST_of_KLASS3-SK_2010.pem',
    'TEST of KLASS3-SK 2016': 'TEST_of_KLASS3-SK_2016.pem',

    # Live certs
    'ESTEID2018': 'ESTEID2018.pem',
    'ESTEID-SK 2007': 'ESTEID-SK_2007.pem',
    'ESTEID-SK 2011': 'ESTEID-SK_2011.pem',
    'ESTEID-SK 2015': 'ESTEID-SK_2015.pem',
    'EID-SK 2011': 'EID-SK_2011.pem',
    'EID-SK 2016': 'EID-SK_2016.pem',
    'KLASS3-SK 2010': 'KLASS3-SK_2010_EECCRCA.pem',
    'KLASS3-SK 2016': 'KLASS3-SK_2016_EECCRCA_SHA384.pem',
    'sk-ocsp-responder-certificates': 'sk-ocsp-responder-certificates.pem',
}

ROOT_CA_FILE_NAME = "EE_Certification_Centre_Root_CA.pem"
TEST_ROOT_CA_FILE_NAME = "TEST_of_EE_Certification_Centre_Root_CA.pem"


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
