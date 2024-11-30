import hashlib
import ctypes
import ctypes.util
import os
import hmac
import simplejson
import base64
import argparse
from pbkdf2 import PBKDF2

import binascii

CLIENT_KEY_NAME = 'Client'

# --------------------------------------------------
# Taken from common_util/keystore/keystore_posix.py
#
# NOTE: original version is based on ncrypt
# http://pypi.python.org/pypi/ncrypt/

#CIPHER_TYPE = CipherType('AES-128', 'CBC')
from Crypto.Cipher import AES

class KeyStoreFileBacked(object):

    def __init__(self, appdata_path):
        self._appdata_path = appdata_path
        self._s = self.id2s(self.unique_id(self._appdata_path))
        self._i = b'l\x078\x014$sX\x03\xffri3\x13aQ'
        self._h = b'\x8f\xf4\xf2\xbb\xad\xe9G\xea\x1f\xdfim\x80[5>'
        self._f = os.path.join(self._appdata_path, 'hostkeys')
        self._dict = None
        # simplified version

    def id2s(self, _id):
        return hashlib.md5(f'ia9{_id}X'.encode('utf-8') + b'a|ui20').digest()

    def obfuscate(self, data):
        encryptor = AES.new(key=self._s, mode=AES.MODE_CBC, IV=self._i)
        return encryptor.encrypt(data)
    
    def _unobfuscate_low(self, data, key):
        decryptor = AES.new(key, mode=AES.MODE_CBC, IV=self._i)
        return decryptor.decrypt(data)

    def unobfuscate(self, data):
        return self._unobfuscate_low(data, self._s), False

    def unversionify_payload(self, data, hmac_keys):
        version = data[0]
        if version not in hmac_keys:
            raise Exception('Parsing error, bad version')
        hm = hmac.new(hmac_keys[version],digestmod=hashlib.md5)
        ds = hm.digest_size
        if len(data) <= ds:
            raise Exception('Bad digest size')
        stored_hm = data[-ds:]
        payload = data[:-ds]
        hm.update(payload)
        if hm.digest() != stored_hm:
            raise Exception('Bad digest')
        return version, payload[1:]

    def _load_dict(self):
        if self._dict is not None:
            return

        with open(self._f, 'rb') as f:
            data = f.read()

        # Overly simplified version
        version, raw_payload = self.unversionify_payload(data, {0: self._h})
        payload, needs_migrate = self.unobfuscate(raw_payload)
        # Manually remove AES-CBC padding ...
        pad = -(payload[-1])
        payload = payload[:pad]
        
        self._dict = simplejson.loads(payload.decode('utf-8'))
        return

    def get_key(self, name):
        self._load_dict()
        return base64.b64decode(self._dict[name])

    def get_versioned_key(self, name, hmac_keys):
        data = self.get_key(name)
        if not data:
            raise Exception('No Data')
        return self.unversionify_payload(data, hmac_keys)

# --------------------------------------------------
# Taken from common_util/keystore/keystore_linux.py

class S(ctypes.Structure):
    _fields_ = [('r1', ctypes.c_ulong),
                ('r2', ctypes.c_ulong),
                ('b1', ctypes.c_ulong),
                ('b2', ctypes.c_ulong),
                ('b3', ctypes.c_ulong),
                ('f1', ctypes.c_ulong),
                ('f2', ctypes.c_ulong),
                ('f3', ctypes.c_ulong),
                ('s1', ctypes.c_ulong),
                ('s2', ctypes.c_int * 128)]

r1 = ctypes.cdll.LoadLibrary(ctypes.util.find_library('c'))
s = r1.statvfs
s.restype = ctypes.c_int
s.argtypes = [ctypes.c_char_p, ctypes.POINTER(S)]

class KeyStore(KeyStoreFileBacked):

    def unique_id(self, path):
        inode = os.stat(path).st_ino
        v = S()
        ret = s(path.encode('utf-8'), ctypes.byref(v))
        if ret < 0:
            raise Exception(f'statvfs failed with retval {ret}')
        # NOTE: original version displays dropbox_hash() instead
        print(f'KEYSTORE: unique_id = {path!r} {inode} {v.s1}')
        return f'{inode}_{v.s1}'

# ---------------------------------------------
# ...

class Version0(object):
    USER_HMAC_KEY = b'\xd1\x14\xa5R\x12e_t\xbdw.7\xe6J\xee\x9b'
    APP_KEY = b'\rc\x8c\t.\x8b\x82\xfcE(\x83\xf9_5[\x8e'
    APP_IV = b'\xd8\x9bC\x1f\xb6\x1d\xde\x1a\xfd\xa4\xb7\xf9\xf4\xb8\r\x05'
    APP_ITER = 1066
    USER_KEYLEN = 16
    DB_KEYLEN = 16

    def new_user_key_and_hmac(self, ks):
        return ks.get_random_bytes(self.USER_KEYLEN), self.USER_HMAC_KEY

    def get_database_key(self, user_key):
        return PBKDF2(passphrase=user_key, salt=self.APP_KEY, iterations=self.APP_ITER).read(self.DB_KEYLEN)

# ---------------------------------------------
# ...

class DBKeyStore(object):

    def __init__(self, appdata_path):
        self.parsers = {0: Version0()}
        self.hmac_keys = {v: self.parsers[v].USER_HMAC_KEY for v in self.parsers}        
        self.ks = KeyStore(appdata_path)
        # simplified version
        # ...
        return
    
    def get_user_key(self):
        version, user_key = self.ks.get_versioned_key(CLIENT_KEY_NAME, self.hmac_keys)
        # Original displays dropbox_hash() instead
        print(f'KEYSTORE: got user key ({version}, {binascii.hexlify(user_key)})')
        return version, user_key

    
# ---------------------------------------------
class Decrypt():
    def __init__(self):
        return
    def Parse(self,appdata_path):
        dbks = DBKeyStore(appdata_path)
        user_key = dbks.get_user_key()
        print(f"User key: {binascii.hexlify(user_key[1])}")

        v0 = Version0()
        db_key = v0.get_database_key(user_key[1])
        print(f"Database key: {binascii.hexlify(db_key)}")
        return db_key

if __name__ == '__main__':
    parser = argparse.ArgumentParser("deb-keygen-linux-v3")
    parser.add_argument("path", help="Path to dbx and hostkeys files", type=str)
    args = parser.parse_args()
    decryptor = Decrypt()
    decryptor.Parse(args.path)             