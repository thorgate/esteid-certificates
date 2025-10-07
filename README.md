# esteid-certificates

[![Coverage Status](https://coveralls.io/repos/github/thorgate/esteid-certificates/badge.svg?branch=main)](https://coveralls.io/github/thorgate/esteid-certificates?branch=main)

This library contains certificates for Estonian electronic identity services and a couple of functions
that facilitate usage.

The library covers the following use cases:
* embedding the root certificate of the Estonian Certification centre into an XML signature structure prior to signing; 
* obtaining OCSP confirmation of the signer's certificate after signing: the OCSP request
  must contain an issuer certificate that corresponds to the issuer's common name
  as included in the signer's certificate.

## API

Get a certificate by issuer's common name:
```python
from esteid_certificates import get_certificate_file_path
# path to PEM certificate file
path = get_certificate_file_name("ESTEID2018")
# the certificate as bytes
with path.open("rb") as f:
    assert f.read().startswith(b"-----BEGIN CERTIFICATE-----")
```

Get the root certificates (also works for test certificates):
```python
from esteid_certificates import get_root_ca_files
for path in get_root_ca_files(test=False):
    with path.open("rb") as f:
        assert f.read().startswith(b"-----BEGIN CERTIFICATE-----")
```

The certificates can be loaded using e.g. the `oscrypto` library:
```python
from oscrypto.asymmetric import load_certificate
from esteid_certificates import get_certificate

cert = load_certificate(get_certificate("ESTEID2018"))
assert cert.asn1.native['tbs_certificate']['subject']['common_name'] == 'ESTEID2018'
```

## Certificates

The certificates were downloaded from [the certificate page](https://www.skidsolutions.eu/repositoorium/sk-sertifikaadid/).

The included certificates are copyright to their issuing parties: 

* [SK ID Solutions AS](https://www.skidsolutions.eu/repositoorium/)

and are redistributed for the sole purpose of convenience of use.

## Updating

See the [update script](autoupdate/README.md) for how to update the certificates.
