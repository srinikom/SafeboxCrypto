#Copyright (c) 2011 Fabula Solutions. All rights reserved.
#Use of this source code is governed by a BSD-style license that can be
#found in the license.txt file.
## crypto

import os, struct, hashlib, hmac, json
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from struct import pack
from binascii import b2a_hex

class SafeboxCrypto(object):
    def __init__(self, pw, in_filename, out_filename):
        self.pw = pw
        self.in_filename = in_filename
        self.out_filename = out_filename
        
    def encrypt(self):
        start = time.time()
        p = ''.join([x for x in self.pw.split('\n') if not re.match('^--', x)])
        try:
            pw = base64.b64decode(p)
        except:
            pw = p
            
        (status, msg) = self.encrypt_file(pw, self.in_filename, self.out_filename)
        if status:    
            print "msg: encrypt", self.in_filename, time.time() - start, "secs"
        else:
            print "err: encrypt", self.in_filename, time.time() - start, "secs"
            sys.stdout.flush()
            
        return status
    
    def decrypt(self):
        start = time.time()
        p = ''.join([x for x in self.pw.split('\n') if not re.match('^--', x)])
        try:
            pw = base64.b64decode(p)
        except:
            pw = p
            
        (status, msg) = self.decrypt_file(pw, self.in_filename, self.out_filename)
        if status:    
            print "msg: decrypt ", self.out_filename, time.time() - start, "secs"
        else:
            print "err: decrypt", self.out_filename, time.time() - start, "secs"
            sys.stdout.flush()
            
        return status
    
    # returns 32x8 = 256 bits
    def gen_salt(self):
        return os.urandom(32)
    
    # returns 16x8 = 128 bits
    def gen_iv(self):
        return os.urandom(16) 
    
    # pbkdf2 -  RSA PKCS#5 v2.0.
    # H(K XOR opad, H(K XOR ipad, text))
    # keylen in bytes - 32 x 8 = 256 bit is key for AES => AES256
    def gen_aes_key(self, pw, salt, keylen=32, iterations=10900, digestmodule=hashlib.sha256):
        return pbkdf2(pw, salt, iterations=iterations).read(keylen)
    
    def gen_auth_key(self, pw, salt, keylen=32, iterations=10500, digestmodule=hashlib.sha256):
        return pbkdf2(pw, salt, iterations=iterations).read(keylen)
                    
    def encrypt_header(self, msg, key, iv):
        encryptor = AES.new(key, AES.MODE_CBC, iv)
        if len(msg) % 16 !=0:
            # PKCS7 - RFC 5652 (CMS)
            msg += chr(16 - len(msg) % 16) * (16 - len(msg) % 16)
        header_block_value = encryptor.encrypt(msg)
        return header_block_value
    
    def decrypt_header(self, msg, key, iv):
        decryptor = AES.new(key, AES.MODE_CBC, iv)
        return decryptor.decrypt(msg)
    
    def encrypt_file(self, pw, in_filename, out_filename, chunksize=64*1024):
        #
        c_info = "AES256"
        version = "1.1" # referred as ve in json
        
        salt = self.gen_salt()
        key = self.gen_aes_key(pw, salt)
        iv = self.gen_iv()
        encryptor = AES.new(key, AES.MODE_CBC, iv)

        filesize = os.path.getsize(in_filename)
        with open(in_filename, 'rb') as infile:
            with open(out_filename, 'wb') as outfile:
                js = json.dumps({'ve': version
                                })
                enc_js = self.encrypt_header(js, key, iv)
                outfile.write(salt)                             # 32 bytes
                outfile.write(iv)                               # 16 bytes
                outfile.write(struct.pack('<H', len(c_info)))   # 2 bytes
                outfile.write(c_info)                            # 6 bytes
                outfile.write(struct.pack('<L', len(enc_js)))   # 4 bytes - length of enc json header string 
                outfile.write(struct.pack('<L', len(js)))       # 4 bytes - length of json header string
                outfile.write(enc_js)                           
                outfile.write(struct.pack('<Q', filesize))      # 8 bytes
                ## Extra bytes - Head
                # 32  - salt
                # 16  - iv
                #> 8  - crypto c_info_len + c_info
                #  8  - encjson string length + json string length
                #>14  - variable - depends on what we put in json
                #  8  - file length
                # ------------------------
                # 86 bytes - 688 bits
    
                while True:
                    chunk = infile.read(chunksize)
                    if len(chunk) == 0:
                        break
                    elif len(chunk) % 16 != 0:
                        # PKCS7 - RFC 5652 (CMS)
                        chunk += chr(16 - len(chunk) % 16) * (16 - len(chunk) % 16)
    
                    outfile.write(encryptor.encrypt(chunk))
                    
        auth_key = self.gen_auth_key(pw, salt)
        auth_code = self.gen_file_auth(auth_key, out_filename)        
        with open(out_filename, 'ab+') as outfile:
            outfile.write(auth_code)  # 32 bytes - auth code
            ## Extra bytes - Tail
            # 32  - auth code
            # ------------------------
            # 32 bytes - 256 bits
            
        return (1, out_filename)
    
    def decrypt_file(self, pw, in_filename, out_filename, chunksize=32*1024):
        with open(in_filename, 'rb') as infile:
            salt = infile.read(32)
            key = self.gen_aes_key(pw, salt)
            iv = infile.read(16)
            
            c_info_len = struct.unpack('<H', infile.read(struct.calcsize('<H')))[0]
            c_info = infile.read(c_info_len)
            enc_js_len = struct.unpack('<L', infile.read(struct.calcsize('<L')))[0]
            js_len = struct.unpack('<L', infile.read(struct.calcsize('<L')))[0]
            msg = self.decrypt_header(infile.read(enc_js_len), key, iv)
            # json exception - if password is incorrect
            try:
                js = json.loads(msg[:js_len])
            except:
                return (0, "Incorrect password/key")
            
            auth_key = self.gen_auth_key(pw, salt)
            if self.verify_file_auth(auth_key, in_filename):
                pass
            else:
                return (0, "File authentication failed. File could be corrupted or modified.")
            
            if c_info == "AES256" and js['ve'] == "1.1":
                origsize = struct.unpack('<Q', infile.read(struct.calcsize('<Q')))[0]
                decryptor = AES.new(key, AES.MODE_CBC, iv)
        
                with open(out_filename, 'wb') as outfile:
                    while True:
                        chunk = infile.read(chunksize)
                        if len(chunk) == 0:
                            break
                        outfile.write(decryptor.decrypt(chunk))
        
                    outfile.truncate(origsize)
            else:
                return (0, "File encryption version is " + js['ve'] + ". This program supports 1.1 and below.")
            
        return (1, out_filename)
    
    # ret 32 byte hmac digest
    def gen_file_auth(self, key, in_filename, chunksize=64*1024):
        h = hmac.new(key, "", hashlib.sha256)
        
        with open(in_filename, 'rb') as infile:
            while True:
                    chunk = infile.read(chunksize)
                    if not chunk:
                        break
                    h.update(chunk)
    
        return h.digest()
    
    # ret T/F 
    def verify_file_auth(self, key, in_filename, chunksize=64*1024):
        h = hmac.new(key, "", hashlib.sha256)
        
        with open(in_filename, 'rb') as infile:
            infile.seek(-32, 2)
            lockfile_size = infile.tell()
            infile_digest = infile.read(32)
            current_seek = 0
            infile.seek(0, 0)
            while True:
                    current_seek += chunksize ;
                    if(current_seek > lockfile_size):
                        rem_chunk = lockfile_size - (current_seek - chunksize)
                        chunk = infile.read(rem_chunk)
                        h.update(chunk)
                        break
                    else:
                        chunk = infile.read(chunksize)
                        if not chunk:
                            break
                        h.update(chunk)
            
        infile.close()
        if h.digest() == infile_digest:
            return True
        else:
            return False
    
class pbkdf2(object):
###########################################################################
# PBKDF2.py - PKCS#5 v2.0 Password-Based Key Derivation
#
# Copyright (C) 2007, 2008 Dwayne C. Litzenberger <dlitz@dlitz.net>
# All rights reserved.
# 
# Permission to use, copy, modify, and distribute this software and its
# documentation for any purpose and without fee is hereby granted,
# provided that the above copyright notice appear in all copies and that
# both that copyright notice and this permission notice appear in
# supporting documentation.
# 
# THE AUTHOR PROVIDES THIS SOFTWARE ``AS IS'' AND ANY EXPRESSED OR 
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES 
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  
# IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, 
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# Country of origin: Canada
#
# Website: https://www.dlitz.net
#
# __version__ = "1.2"
    def __init__(self, passphrase, salt, iterations=10000,
                 digestmodule=hashlib.sha256, macmodule=hmac):
        self.__macmodule = macmodule
        self.__digestmodule = digestmodule
        self._setup(passphrase, salt, iterations, self._pseudorandom)

    def _pseudorandom(self, key, msg):
        """Pseudorandom function.  e.g. HMAC-hashlib.sha256"""
        return self.__macmodule.new(key=key, msg=msg,
            digestmod=self.__digestmodule).digest()
    
    def read(self, bytes):
        """Read the specified number of key bytes."""
        if self.closed:
            raise ValueError("file-like object is closed")

        size = len(self.__buf)
        blocks = [self.__buf]
        i = self.__blockNum
        while size < bytes:
            i += 1
            if i > 0xffffffffL or i < 1:
                # We could return "" here, but 
                raise OverflowError("derived key too long")
            block = self.__f(i)
            blocks.append(block)
            size += len(block)
        buf = "".join(blocks)
        retval = buf[:bytes]
        self.__buf = buf[bytes:]
        self.__blockNum = i
        return retval
    
    def strxor(self, a, b):
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b)])
    
    def __f(self, i):
        # i must fit within 32 bits
        assert 1 <= i <= 0xffffffffL
        U = self.__prf(self.__passphrase, self.__salt + pack("!L", i))
        result = U
        for j in xrange(2, 1+self.__iterations):
            U = self.__prf(self.__passphrase, U)
            result = self.strxor(result, U)
        return result
    
    def hexread(self, octets):
        """Read the specified number of octets. Return them as hexadecimal.

        Note that len(obj.hexread(n)) == 2*n.
        """
        return b2a_hex(self.read(octets))

    def _setup(self, passphrase, salt, iterations, prf):
        # Sanity checks:
        
        # passphrase and salt must be str or unicode (in the latter
        # case, we convert to UTF-8)
        if isinstance(passphrase, unicode):
            passphrase = passphrase.encode("UTF-8")
        if not isinstance(passphrase, str):
            raise TypeError("passphrase must be str or unicode")
        if isinstance(salt, unicode):
            salt = salt.encode("UTF-8")
        if not isinstance(salt, str):
            raise TypeError("salt must be str or unicode")

        # iterations must be an integer >= 1
        if not isinstance(iterations, (int, long)):
            raise TypeError("iterations must be an integer")
        if iterations < 1:
            raise ValueError("iterations must be at least 1")
        
        # prf must be callable
        if not callable(prf):
            raise TypeError("prf must be callable")

        self.__passphrase = passphrase
        self.__salt = salt
        self.__iterations = iterations
        self.__prf = prf
        self.__blockNum = 0
        self.__buf = ""
        self.closed = False
    
    def close(self):
        """Close the stream."""
        if not self.closed:
            del self.__passphrase
            del self.__salt
            del self.__iterations
            del self.__prf
            del self.__blockNum
            del self.__buf
            self.closed = True
            
