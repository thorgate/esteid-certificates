# Autoupdater for SK certificates

Uses beautiful soup and requests to get currently valid certificates from SK's website. 

## Usage

```shell
cd autoupdate
just update
```

You may want to inspect changes to constants.py and if any of the certificates
are gone you can delete them from `esteid_certificates/files` directory.

## Steps to take manually after autoupdate
* Check that the certificates are correct. Never should you commit and publish a package without checking that
  the data is actually valid
* Increment version in `esteid_certificates/__init__.py`
* Add a new entry to `CHANGELOG.md`
* Commit changes and push to GitHub
* Test the changes
* Publish the package to PyPi (currently, needs manual steps)
