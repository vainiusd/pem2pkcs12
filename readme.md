## Usage

```
$ ./pem_to_pkcs12.py -h
usage: pem_to_pkcs12.py [-h] -d FILE_DIR -s SECRET [-o OUTPUT]

LE PEM converter to PKCS12

optional arguments:
  -h, --help            show this help message and exit
  -d FILE_DIR, --file_dir FILE_DIR
                        Path to Let's Encrypt generated files ($RENEWED_LINEAGE)
  -s SECRET, --secret SECRET
                        PKSC12 password
  -o OUTPUT, --output OUTPUT
                        PKSC12 output file
```