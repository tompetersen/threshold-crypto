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
import json


class ThresholdCryptoError(Exception):
    pass


class ThresholdParameters:
    """
    Contains the parameters used for the threshold scheme:
    - t: number of share owners required to decrypt a message
    - n: number of share owners involved

    In other words:
    At least t out of overall n share owners must participate to decrypt an encrypted message.
    """

    @staticmethod
    def from_json(json_str: str):
        obj = json.loads(json_str)
        return ThresholdParameters.from_dict(obj)

    @staticmethod
    def from_dict(obj: dict):
        return ThresholdParameters(obj['t'], obj['n'])

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

        self._t = t
        self._n = n

    @property
    def t(self) -> int:
        return self._t

    @property
    def n(self) -> int:
        return self._n

    def to_dict(self):
        return {
            't': self._t,
            'n': self._n
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    def __eq__(self, other):
        return (isinstance(other, self.__class__) and
               self.t == other.t and
               self.n == other.n)

    def __str__(self):
        return 'ThresholdParameters: t = %d, n = %d)' % (self._t, self._n)


class KeyParameters:
    """
    Contains the key parameters the scheme uses:
    - Primes p, q with p = 2q + 1
    - Generator g of q-ordered subgroup Z_q* of Z_p*
    """

    @staticmethod
    def from_json(json_str: str):
        obj = json.loads(json_str)
        return KeyParameters.from_dict(obj)

    @staticmethod
    def from_dict(obj: dict):
        return KeyParameters(obj['p'], obj['q'], obj['g'])

    def __init__(self, p: int, q: int, g: int):
        """
        Construct key parameters. Required:
        - p = 2q + 1
        - g generates Z_q*, meaning (g^q mod p = 1) and (g^2 mod p != 1)
          These conditions are sufficient because subgroups of Z_p* can only have orders 1, 2, q or 2q.

        :param p: prime
        :param q: prime
        :param g: generator for Z_q*
        """
        if (2 * q + 1) != p:
            raise ThresholdCryptoError('no safe prime (p = 2q + 1) given')
        if pow(g, q, p) != 1 or pow(g, 2, p) == 1:
            raise ThresholdCryptoError('no generator g for subgroup of order q given')

        self._p = p
        self._q = q
        self._g = g

    @property
    def p(self) -> int:
        return self._p

    @property
    def q(self) -> int:
        return self._q

    @property
    def g(self) -> int:
        return self._g

    def to_dict(self):
        return {
            'p': self._p,
            'q': self._q,
            'g': self._g
        }

    def to_json(self):
        return json.dumps(self.to_dict())

    def __eq__(self, other):
        return (isinstance(other, self.__class__) and
                self.p == other.p and
                self.q == other.q and
                self.g == other.g)

    def __str__(self):
        return 'KeyParameters:\n\tp = %d\n\tq = %d\n\tg = %d' % (self._p, self._q, self._g)


class PublicKey:
    """
    The public key (g^a mod p) linked to the (implicit) secret key (a) of the scheme.
    """

    @staticmethod
    def from_json(json_str: str):
        obj = json.loads(json_str)
        return PublicKey.from_dict(obj)

    @staticmethod
    def from_dict(obj: dict):
        key_params = KeyParameters.from_dict(obj)
        return PublicKey(obj['g_a'], key_params)

    def __init__(self, g_a: int, key_params: KeyParameters):
        """
        Construct the public key.

        :param g_a: the public key value
        :param key_params: the key parameters used for constructing the key.
        """
        if key_params is None:
            raise ThresholdCryptoError('key parameters must be given')

        self._g_a = g_a
        self._key_params = key_params

    @property
    def g_a(self) -> int:
        return self._g_a

    @property
    def key_parameters(self) -> KeyParameters:
        return self._key_params

    def to_dict(self):
        return {
            'p': self._key_params.p,
            'q': self._key_params.q,
            'g': self._key_params.g,
            'g_a': self._g_a,
        }

    def to_json(self):
        return json.dumps(self.to_dict())

    def __eq__(self, other):
        return (isinstance(other, self.__class__) and
                self.key_parameters == other.key_parameters and
                self.g_a == other.g_a)

    def __str__(self):
        return 'PublicKey:\n\tg^a = ' + str(self._g_a)


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
    - c = r * g^k mod p as in the ElGamal scheme with r being the value to be encrypted
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

