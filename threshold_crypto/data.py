"""
A stateless library which offers functionality for ElGamal-based threshold decryption with centralized key generation.

Threshold decryption means a message can be encrypted using a simple public key, but for decryption at least t out of n
share owners must collaborate to decrypt the message.

A hybrid approach (using pynacl for symmetric encryption) is used for message encryption and decryption.
Therefor there are no limitations regarding message lengths or format. Additionally the integrity of a message is
secured by using the AE-scheme, meaning changes to some parts of the ciphertext, to partial decryptions or even
dishonest share owners can be detected.

Usage:
    # Generate parameters, public key and shares
    key_params = ThresholdCrypto.static_2048_key_parameters()
    thresh_params = ThresholdParameters(3, 5)
    pub_key, key_shares = ThresholdCrypto.create_public_key_and_shares_centralized(key_params, thresh_params)

    # encrypt message using the public key
    message = 'Some secret message to be encrypted!'
    encrypted_message = ThresholdCrypto.encrypt_message(message, pub_key)

    # build partial decryptions of three share owners using their shares
    reconstruct_shares = [key_shares[i] for i in [0, 2, 4]]
    partial_decryptions = [ThresholdCrypto.compute_partial_decryption(encrypted_message, share) for share in reconstruct_shares]

    # combine these partial decryptions to recover the message
    decrypted_message = ThresholdCrypto.decrypt_message(partial_decryptions, encrypted_message, thresh_params, key_params)
"""
import base64
import collections
import json

from Crypto.PublicKey import ECC


class ThresholdCryptoError(Exception):
    pass


class ThresholdDataClass:
    """ Baseclass for ThresholdCrypto data classes. """
    CURVE_MAGIC = "ECURVE|"

    def __init__(self):
        raise NotImplementedError("Implement __init__ in subclass when using ThresholdDataClass")

    def to_json(self):
        """ Create json representation of object. Some special cases are already handled here. """
        dict = self.__dict__.copy()

        for k in dict:
            # special handling of curve parameters
            if isinstance(dict[k], CurveParameters):
                dict[k] = self.CURVE_MAGIC + dict[k]._name

            # special handling of curve points
            if isinstance(dict[k], ECC.EccPoint):
                p = dict[k]
                dict[k] = {
                    "x": int(p.x),
                    "y": int(p.y),
                    "curve": p._curve_name,
                }

        return json.dumps(dict)

    @classmethod
    def from_json(cls, json_str: str):
        """ Create object from json representation. Some special cases are already handled here. """
        dict = json.loads(json_str)

        for k in dict:
            # special handling of curve parameters
            if isinstance(dict[k], str) and dict[k].startswith(cls.CURVE_MAGIC):
                dict[k] = CurveParameters(curve_name=dict[k][len(cls.CURVE_MAGIC):])

            # special handling of curve points
            if isinstance(dict[k], collections.Mapping) and "x" in dict[k] and "y" in dict[k] and "curve" in dict[k]:
                dict[k] = ECC.EccPoint(**dict[k])

        return cls(**dict)


class ThresholdParameters(ThresholdDataClass):
    """
    Contains the parameters used for the threshold scheme:
    - t: number of share owners required to decrypt a message
    - n: number of share owners involved

    In other words:
    At least t out of overall n share owners must participate to decrypt an encrypted message.
    """

    def __init__(self, t: int, n: int):
        """
        Construct threshold parameter. Required:
        0 < t <= n

        :param t:  number of share owners required for decryption
        :param n: overall number of share owners
        """
        if t > n:
            raise ThresholdCryptoError('threshold parameter t must be smaller than n')
        if t <= 0:
            raise ThresholdCryptoError('threshold parameter t must be greater than 0')

        self.t = t
        self.n = n

    def __eq__(self, other):
        return (isinstance(other, self.__class__) and
                self.t == other.t and
                self.n == other.n)

    def __str__(self):
        return 'ThresholdParameters ({}, {})'.format(self.t, self.n)


class CurveParameters(ThresholdDataClass):
    """
    Contains the curve parameters the scheme uses. Since PyCryptodome is used, only curves present there are available:
    https://pycryptodome.readthedocs.io/en/latest/src/public_key/ecc.html
    """
    DEFAULT_CURVE = 'P-256'

    def __init__(self, curve_name: str = DEFAULT_CURVE):
        """
        Construct the curve from a given curve name (according to curves present in PyCryptodome).

        :param curve_name:
        """
        if curve_name not in ECC._curves:
            raise ThresholdCryptoError('Unsupported curve: ' + curve_name)

        self._name = curve_name
        self._curve = ECC._curves[curve_name]
        self.P = ECC.EccPoint(x=self._curve.Gx, y=self._curve.Gy, curve=curve_name)

    @property
    def order(self):
        return int(self._curve.order)

    def to_json(self):
        return json.dumps({'curve_name': self._name})

    def __eq__(self, other):
        return (isinstance(other, self.__class__) and
                self._curve == other._curve)

    def __str__(self):
        return "Curve {} of order {} with generator point P = {}".format(self._name, self.order, self.P)


class PublicKey(ThresholdDataClass):
    """
    The public key point Q linked to the (implicit) secret key d of the scheme.
    """

    def __init__(self, Q: ECC.EccPoint, curve_params: CurveParameters = CurveParameters()):
        """
        Construct the public key.

        :param Q: the public key point Q = dP
        :param curve_params: the curve parameters used for constructing the key.
        """
        self.Q = Q
        self.curve_params = curve_params

    def __eq__(self, other):
        return (isinstance(other, self.__class__) and
                self.curve_params == other.curve_params and
                self.Q == other.Q)

    def __str__(self):
        return 'Public key point Q = {} (on curve {})'.format(self.Q, self.curve_params._name)


class KeyShare:
    """
    A share (x_i, y_i) of the private key for share owner i.
    y_i is the evaluated polynom value of x_i in shamirs secret sharing.
    """

    @staticmethod
    def from_json(json_str: str):
        obj = json.loads(json_str)
        return KeyShare.from_dict(obj)

    @staticmethod
    def from_dict(obj: dict):
        key_params = KeyParameters.from_dict(obj)
        return KeyShare(obj['x'], obj['y'], key_params)

    def __init__(self, x: int, y: int, key_params: KeyParameters):
        """
        Construct a share of the private key.

        :param x: the x value of the share
        :param y: the y value of the share
        :param key_params:
        """
        if key_params is None:
            raise ThresholdCryptoError('key parameters must be given')

        self._x = x
        self._y = y
        self._key_params = key_params

    @property
    def x(self) -> int:
        return self._x

    @property
    def y(self) -> int:
        return self._y

    @property
    def key_parameters(self) -> KeyParameters:
        return self._key_params

    def to_dict(self):
        return {
            'p': self.key_parameters.p,
            'q': self.key_parameters.q,
            'g': self.key_parameters.g,
            'x': self.x,
            'y': self.y,
        }

    def to_json(self):
        return json.dumps(self.to_dict())

    def __eq__(self, other):
        return (isinstance(other, self.__class__) and
                self.key_parameters == other.key_parameters and
                self.x == other.x and
                self.y == other.y)

    def __str__(self):
        return 'KeyShare:\n\tx = %d\n\ty = %d' % (self._x, self._y)


class EncryptedMessage:
    """
    An encrypted message in the scheme. Because a hybrid approach is used it consists of three parts:
    - v = g^k mod p as in the ElGamal scheme
    - c = r * g^ak mod p as in the ElGamal scheme with r being the value to be encrypted
    - enc the symmetrically encrypted message.
    The symmetric key is derived from the ElGamal encrypted value r.
    """

    @staticmethod
    def from_json(json_str: str):
        obj = json.loads(json_str)
        return EncryptedMessage.from_dict(obj)

    @staticmethod
    def from_dict(obj: dict):
        return EncryptedMessage(obj['v'], obj['c'], obj['enc'])

    def __init__(self, v: int, c: int, enc: str):
        """
        Construct a encrypted message.

        :param v: like in ElGamal scheme
        :param c: like in ElGamal scheme
        :param enc: the symmetrically encrypted message
        """
        self._v = v
        self._c = c
        self._enc = enc

    @property
    def v(self) -> int:
        return self._v

    @property
    def c(self) -> int:
        return self._c

    @property
    def enc(self) -> str:
        return self._enc

    def to_dict(self):
        return {
            'v': self.v,
            'c': self.c,
            'enc': self.enc,
        }

    def to_json(self):
        return json.dumps(self.to_dict())

    def __eq__(self, other):
        return (isinstance(other, self.__class__) and
                self.v == other.v and
                self.c == other.c and
                self.enc == other.enc)

    def __str__(self):
        return 'EncryptedMessage:\n\tv = %d\n\tc = %d\n\tenc = %s' % (self._v, self._c, self._enc)


class PartialDecryption:
    """
    A partial decryption (x_i, v^(y_i)) of an encrypted message computed by a share owner using his share.
    """

    @staticmethod
    def from_json(json_str: str):
        obj = json.loads(json_str)
        return PartialDecryption.from_dict(obj)

    @staticmethod
    def from_dict(obj: dict):
        return PartialDecryption(obj['x'], obj['v_y'])

    def __init__(self, x: int, v_y: int):
        """
        Construct the partial decryption.

        :param x: the shares x value
        :param v_y: the computed partial decryption value
        """
        self._x = x
        self._v_y = v_y

    @property
    def x(self) -> int:
        return self._x

    @property
    def v_y(self) -> int:
        return self._v_y

    def to_dict(self):
        return {
            'x': self.x,
            'v_y': self.v_y,
        }

    def to_json(self):
        return json.dumps(self.to_dict())

    def __eq__(self, other):
        return (isinstance(other, self.__class__) and
                self.x == other.x and
                self.v_y == other.v_y)

    def __str__(self):
        return 'PartialDecryption:\n\tx = %d\n\tv^y = %d' % (self._x, self._v_y)


class PartialReEncryptionKey:
    """
    TBD
    """

    def __init__(self, partial_key: int, key_params: KeyParameters):
        """
        TBD
        :param partial_key: The difference of (λ2_i * y2_i - λ1_i * y1_i) where *1 are the old and *2 the new components
        """
        self.partial_key = partial_key
        self.key_params = key_params


class ReEncryptionKey:
    """
    TBD
    """

    def __init__(self, key, key_params: KeyParameters):
        """

        :param key: the reencryption key (y2 - y1) meaning old private key minus new private key
        """
        self.key = key
        self.key_params = key_params
