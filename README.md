# Dropbox DBX File Decryptor

This tool is designed to decrypt Dropbox `dbx` files that contain encrypted configuration or data blobs. It uses a combination of private keys and timestamp-based initialization vectors to recover the original data.

The tool supports automatic decompression and checksum validation to ensure the integrity of the decrypted content.

based on https://github.com/newsoft/dbx-keygen-linux
---

## Features
- Decrypts `dbx` files and associated host keys.
- Automatically validates and decompresses decrypted blobs.
- Brute-forces timestamps to recover initialization vectors (IVs) within a specified time range.
- Handles large files efficiently.

---

## Requirements
Works on Python 3.12.3
The following Python dependencies are required:
- `pycryptodome==3.21.0`
- `simplejson==3.19.3`
- `pbkdf2==1.3`

## Install
```bash
git clone https://github.com/takyoni/dbx-keygen-linux-v3.git
cd dbx-keygen-linux-v3
pip install -r requirements.txt
```

## Usage
Run the tool from the command line:

```bash
python3 Decryptor.py <path>
```

### Parameters:
path: Path to the folder containing the dbx and hostkeys files.

```bash
python Decryptor.py /home/user/.dropbox/instance1
```

## Example

```bash
user@DESKTOP-PTD7JMT:/mnt/e/dbx-keygen-linux-v3$ python3 Decryptor.py /home/user/.dropbox/instance1
KEYSTORE: unique_id = '/home/user/.dropbox/instance1'
KEYSTORE: got user key (0, b'h5ykh5lg5e568i7vrmonquggbnfug4e9')
User key: b'h5ykh5lg5e568i7vrmonquggbnfug4e9'
Database key: b'g3ldid2a5q9bvr91y5x5c8s66ngw6iit'
```

Then use this [repo](https://github.com/newsoft/sqlite3-dbx) to decypt dbx with database key
