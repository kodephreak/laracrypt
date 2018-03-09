"""
Tested on Python 3.6
Installing Dependencies:
    pip install pycryptodome phpserialize

"""

import os
import base64
import json
from Crypto.Cipher import AES
from phpserialize import loads, dumps
import hashlib
import hmac


class DecryptException(Exception):
    pass


class LaraCrypt:

    def __init__(self, key):
        # In Laravel, encryption key is stored in base64 format in the .env file.
        # The format for the key is base64:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
        # You can either pass in the key value directly as is or you can strip the base64: off yourself.

        if key.startswith("base64:"):
            key = key[len("base64:"):]

        # Key is stored as base 64 encoded and we want to make sure to convert them back to the raw
        # bytes before encrypting.
        self.key = base64.b64decode(key)

    def encrypt(self, plain_text, serialize=True):
        """
        Method to encrypt a plain text into Laravel supported encrypted string

        :param plain_text: string Plain text
        :param serialize: boolean
        :return: string Returns encrypted string
        """
        iv = os.urandom(16)

        # Serialize or convert the payload into bytes
        if serialize:
            payload = dumps(plain_text)
        else:
            payload = plain_text.encode('utf-8')

        value = base64.b64encode(
            AES.new(key=self.key, mode=AES.MODE_CBC, IV=iv).encrypt(self._pad(payload.decode()).encode()))

        # Once we get the encrypted value we'll go ahead and base64_encode the input
        # vector and create the MAC for the encrypted value so we can then verify
        # its authenticity. Then, we'll JSON the data into the "payload" array.

        iv = base64.b64encode(iv)
        mac = self._hash(iv, value)

        return base64.b64encode(json.dumps({'iv': iv.decode(), 'value': value.decode(), 'mac': mac}).encode("utf-8"))

    def decrypt(self, payload, unserialize=True):
        """
        Method to decrypt Laravel encrypted string

        :param payload: string Encrypted string
        :param unserialize: boolean
        :return: string Returns plain text
        """

        payload = self._get_json_payload(payload)

        iv = base64.b64decode(payload['iv'].encode('utf-8'))
        value = base64.b64decode(payload['value'].encode('utf-8'))

        serialized_text = self._unpad(AES.new(key=self.key, mode=AES.MODE_CBC, IV=iv).decrypt(value))
        if unserialize:
            return loads(serialized_text).decode()
        return serialized_text.decode()

    def _get_json_payload(self, payload):
        """
        Decodes and gets back the json object from the encrypted string

        :param payload: string Encrypted string
        :return: dict A dictionary containing IV, Value and MAC
        """
        payload = json.loads(base64.b64decode(payload).decode())

        # If the payload is not valid JSON or does not have the proper keys set we will
        # assume it is invalid and bail out of the routine since we will not be able
        # to decrypt the given value. We'll also check the MAC for this encryption.
        if not self._is_valid_payload(payload) or not self._is_valid_mac(payload):
            raise DecryptException("Unable to decrypt. The payload is invalid.")

        return payload

    @staticmethod
    def _is_valid_payload(payload):
        """
        Check if the payload is a dictionary with the specific keys

        :param payload: dict
        :return: boolean
        """
        if isinstance(payload, dict):
            if all(k in payload for k in ("iv", "value", "mac")):
                # Check if all the keys have some value
                if payload['iv'] and payload['value'] and payload['mac']:
                    return True

    def _is_valid_mac(self, payload):
        """
        Determine if the MAC for the given payload is valid.

        :param payload: dict
        :return: boolean
        """
        random_bytes = os.urandom(16)
        calculated_mac = self._calculate_mac(payload, random_bytes)
        return hmac.compare_digest(
            hmac.new(random_bytes, payload['mac'].encode('utf-8'), hashlib.sha256).digest(), calculated_mac)

    def _calculate_mac(self, payload, random_bytes):
        """
        Calculate the hash of the given payload.

        :param payload: boolean
        :param random_bytes: bytes
        :return: hash
        """
        iv = payload['iv'].encode("utf-8")
        value = payload['value'].encode("utf-8")

        return hmac.new(
            random_bytes, self._hash(iv, value).encode('utf-8'), hashlib.sha256).digest()

    def _hash(self, iv, value):
        """
        Create a MAC for the given value.

        :param iv: bytes
        :param value: bytes
        :return: hash
        """
        return hmac.new(self.key, iv + value, hashlib.sha256).hexdigest()

    @staticmethod
    def _pad(s):
        """
        Padding data to 16 byte boundary for CBC mode

        :param s: bytes
        :return: bytes
        """
        return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

    @staticmethod
    def _unpad(s):
        """
        Unpadding additional padded bytes to get the clean plain text

        :param s: bytes
        :return: bytes
        """
        return s[:-ord(s[len(s) - 1:])]


if __name__ == '__main__':
    lc = LaraCrypt("base64:BlNhkCOTgNvgESHX8M+CIOISy7Jk3UAfufKfJVcVEck=")
    print(lc.decrypt(lc.encrypt("Hello World!")))


