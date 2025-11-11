# Changelog for esteid-certificates

## Version 1.0.4, 2025-11-11

* Implement Zetes certificate automatic upgrade
* Add Zetes live certificates
* Add Zetes test certificates
* Add latest SK certificates
* Deprecate `get_root_ca_file_name` and `get_root_certificate`, which do not support multiple trust service providers, 
  in favor of `get_root_ca_files` and `get_root_certificates`
* Add `get_certificate_file_path` with pathlib support

## Version 1.0.3, 2025-03-18

* Add 2025 timestamping certificates
* Remove 2020 timestamping certificate
* Fix typo in constants.py

## Version 1.0.2, 2024-10-15

* Add autoupdater script 
* Update to use the newest certificates
* Add all valid certificates from TSA certificates tab on SK's website
* Remove sk-ocsp-responder-certificates from the package, as they expired (and all OCSP certificates are listed as expired)

## Version 1.0.1, 2020-10-27

* Add sk-ocsp-responder-certificates to the package

## Version 1.0, 2020-10-07

* Initial version
