# esteid-certificates

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
from esteid_certificates import get_certificate_file_name, get_certificate
# path to PEM certificate file
assert get_certificate_file_name("EID-SK 2016").endswith(".pem")
# the certificate as bytes
assert get_certificate("EID-SK 2016").startswith(b"-----BEGIN CERTIFICATE-----")
```

Get the root certificate:
```python
from esteid_certificates import get_root_ca_file_name, get_root_certificate
# path to PEM certificate file
assert get_root_ca_file_name().endswith(".pem")
# the certificate as bytes
assert get_root_certificate().startswith(b"-----BEGIN CERTIFICATE-----")
```

Get the TEST root certificate:
```python
from esteid_certificates import get_root_ca_file_name, get_root_certificate
# path to PEM certificate file
assert get_root_ca_file_name(test=True).endswith(".pem")
# the certificate as bytes
assert get_root_certificate(test=True).startswith(b"-----BEGIN CERTIFICATE-----")
```

The certificates can be loaded using e.g. the `oscrypto` library:
```python
from oscrypto.asymmetric import load_certificate
cert = load_certificate(get_certificate("EID-SK 2016"))
assert cert.asn1.native['tbs_certificate']['subject']['common_name'] == 'EID-SK 2016'
```

## Certificates

The certificates were downloaded from [the certificate page](https://www.skidsolutions.eu/repositoorium/sk-sertifikaadid/).

The included certificates are copyright to their issuing parties: 

* [SK ID Solutions AS](https://www.skidsolutions.eu/repositoorium/)

and are redistributed for the sole purpose of convenience of use.
