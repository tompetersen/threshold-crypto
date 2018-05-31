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

import nacl.utils
import nacl.secret
import nacl.encoding
import nacl.exceptions
import nacl.hash

from threshold_crypto import number


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


class ThresholdCrypto:

    @staticmethod
    def static_512_key_parameters() -> KeyParameters:
        p = 7452962895294639129334402125897500494888232626693057568141676237916133687836239813279595639173262006234190877985012715032067188198462763852940914332974923
        q = 3726481447647319564667201062948750247444116313346528784070838118958066843918119906639797819586631003117095438992506357516033594099231381926470457166487461
        g = 1291791552707048245090176929539921926555612768576578304996066408519254635531597933040589792119803333400907701386210407460215915386675734438575583315866662

        return KeyParameters(p=p, q=q, g=g)

    @staticmethod
    def static_1024_key_parameters() -> KeyParameters:
        p = 91926125049667098586079247877954763240710944754791290600171879145842202844582766445861279297301599420441349450624904680670028101087907202676187927298703453013677139241144888658781102160172206621554562245692688934838467931639759244893636532792266365772257680539051728298486982205394534973908616156393244207739
        q = 45963062524833549293039623938977381620355472377395645300085939572921101422291383222930639648650799710220674725312452340335014050543953601338093963649351726506838569620572444329390551080086103310777281122846344467419233965819879622446818266396133182886128840269525864149243491102697267486954308078196622103869
        g = 70818045059412229096505272235743689389634686118918223401102407992390386472684584481028357968153236944027127686728774077632802000371835496959768179869988907055346762739460056524883039694157166386370062954387939133203886044147537199513403531355494899326175829610159895944695633468594258300316101218892509250468

        return KeyParameters(p=p, q=q, g=g)

    @staticmethod
    def static_2048_key_parameters() -> KeyParameters:
        p = 21236934862218511653623447364710811485097463859632312183494470321865437684383737237095118043782630953663551424644349676344051737646575908035229445418970350579998208464171222735264502195941087943912660267879360376600529021906143975135547131090543473264136217654462045160443124694552287906754023396731536363634457064852718052465363129643486360313019964341460374106944280350493228300541853254188973394324275526119409082151906335458925803081691961627262872909544911250939426559669641181741418792650389621395244191383680090126152455331128151622579879305128105513594663146479955290034772381144185556023460209436347971723223
        q = 10618467431109255826811723682355405742548731929816156091747235160932718842191868618547559021891315476831775712322174838172025868823287954017614722709485175289999104232085611367632251097970543971956330133939680188300264510953071987567773565545271736632068108827231022580221562347276143953377011698365768181817228532426359026232681564821743180156509982170730187053472140175246614150270926627094486697162137763059704541075953167729462901540845980813631436454772455625469713279834820590870709396325194810697622095691840045063076227665564075811289939652564052756797331573239977645017386190572092778011730104718173985861611
        g = 17906435243842862345453835552815243404911647137073134463025160688995967488398983883106245967559373149795748443813049871354204770601174285653863536485679014760802852938205445698233430999295273593565745966645968651501470796614660949221379136782521156980440939610488754701132825226698633081421678693978649121584859440571365037320084373304699863718759566935084604920447588793835852015570107152381880424069367528899745747855775959412017686801090474997082475612446031206581849434853823922623275250452328283036003031659299664036862958862229602762586321240949493048947451750791435815161649573142989093624189059486316195524206

        return KeyParameters(p=p, q=q, g=g)

    @staticmethod
    def generate_key_parameters(key_size: int) -> KeyParameters:
        """
        Generates new random key parameters of size key_size.

        :param key_size: the key size in bits
        :return: the key parameters containing p, q and g.
        """

        # Create safe primes
        while True:
            q = number.getPrime(key_size - 1)
            p = 2 * q + 1
            if number.isPrime(p):
                break

        # Create generator of subgroup of order q.
        #
        # Since subgroups can just have the orders 1, 2, q, 2q=p-1 testing is easy.
        # https://crypto.stackexchange.com/questions/7983/elgamal-generation-of-g-value
        # https://crypto.stackexchange.com/questions/1451/elgamal-multiplicative-cyclic-group-and-key-generation
        while True:
            g = number.getRandomRange(3, p - 2)
            if (pow(g, q, p) == 1 and pow(g, 2, p) != 1):
                break

        return KeyParameters(p, q, g)


    @staticmethod
    def create_public_key_and_shares_centralized(key_params: KeyParameters, threshold_params: ThresholdParameters) -> (PublicKey, [KeyShare]):
        """
        Creates a public key and n shares by choosing a random secret key and using it for computations.

        :param key_params: key parameters to use
        :param threshold_params: parameters t and n for the threshold scheme
        :return: (the public key, n key shares)
        """
        a = number.getRandomRange(2, key_params.q - 2)
        g_a = pow(key_params.g, a, key_params.p)
        public_key = PublicKey(g_a, key_params)

        # Perform Shamir's secret sharing in Z_q
        polynom = number.PolynomMod.create_random_polynom(a, threshold_params.t - 1, key_params.q)
        supporting_points = range(1, threshold_params.n + 1)
        shares = [KeyShare(x, polynom.evaluate(x), key_params) for x in supporting_points]

        return public_key, shares

    @staticmethod
    def encrypt_message(message: str, public_key: PublicKey) -> EncryptedMessage:
        """
        Encrypt a message using a public key. A hybrid encryption approach is used to include advantages of symmetric
        encryption (fast, independent of message-length, integrity-preserving by using AE-scheme).
        Internally a combination of Salsa20 and Poly1305 from the cryptographic library NaCl is used.
        
        :param message: the message to be encrypted
        :param public_key: the public key
        :return: an encrypted message
        """
        encoded_message = bytes(message, 'utf-8')
        key_params = public_key.key_parameters

        # Create random subgroup element and use its hash as symmetric key to prevent
        # attacks described in "Why Textbook ElGamal and RSA Encryption Are Insecure"
        # by Boneh et. al.
        r = number.getRandomRange(2, public_key.key_parameters.q)
        key_subgroup_element = pow(key_params.g, r, key_params.p)
        key_subgroup_element_byte_length = (key_subgroup_element.bit_length() + 7) // 8
        element_bytes = key_subgroup_element.to_bytes(key_subgroup_element_byte_length, byteorder='big')

        try:
            symmetric_key = nacl.hash.blake2b(element_bytes,
                                              digest_size=nacl.secret.SecretBox.KEY_SIZE,
                                              encoder=nacl.encoding.RawEncoder)
            # Use derived symmetric key to encrypt the message
            box = nacl.secret.SecretBox(symmetric_key)
            encrypted = box.encrypt(encoded_message).hex()
        except nacl.exceptions.CryptoError as e:
            print('Encryption failed: ' + str(e))
            raise ThresholdCryptoError('Message encryption failed.')

        # Use threshold scheme to encrypt the subgroup element used as hash input to derive the symmetric key
        g_k, c = ThresholdCrypto._encrypt_key_element(key_subgroup_element, public_key)

        return EncryptedMessage(g_k, c, encrypted)

    @staticmethod
    def _encrypt_key_element(key_element: int, public_key: PublicKey) -> (int, int):
        key_params = public_key.key_parameters

        if key_element >= key_params.p:
            raise ThresholdCryptoError('key element is larger than key parameter p')

        k = number.getRandomRange(1, key_params.q - 1)
        g_k = pow(key_params.g, k, key_params.p) # aka v
        g_ak = pow(public_key.g_a, k, key_params.p)
        c = (key_element * g_ak) % key_params.p

        return g_k, c

    @staticmethod
    def compute_partial_decryption(encrypted_message: EncryptedMessage, key_share: KeyShare) -> PartialDecryption:
        """
        Compute a partial decryption of an encrypted message using a key share.

        :param encrypted_message: the encrypted message
        :param key_share: the key share
        :return: a partial decryption
        """
        key_params = key_share.key_parameters

        v_y = pow(encrypted_message.v, key_share.y, key_params.p)

        return PartialDecryption(key_share.x, v_y)

    @staticmethod
    def decrypt_message(partial_decryptions: [PartialDecryption],
                        encrypted_message: EncryptedMessage,
                        threshold_params: ThresholdParameters,
                        key_params: KeyParameters
                        ) -> str:
        """
        Decrypt a message using the combination of at least t partial decryptions. Similar to the encryption process
        the hybrid approach is used for decryption.

        :param partial_decryptions: at least t partial decryptions
        :param encrypted_message: the encrapted message to be decrypted
        :param threshold_params: the used threshold parameters
        :param key_params: the used key parameters
        :return: the decrypted message
        """
        key_subgroup_element = ThresholdCrypto._combine_shares(
            partial_decryptions,
            encrypted_message,
            threshold_params,
            key_params
        )
        key_subgroup_element_byte_length = (key_subgroup_element.bit_length() + 7) // 8
        key_subgroup_element_bytes = key_subgroup_element.to_bytes(key_subgroup_element_byte_length, byteorder='big')

        try:
            key = nacl.hash.blake2b(key_subgroup_element_bytes,
                                    digest_size=nacl.secret.SecretBox.KEY_SIZE,
                                    encoder=nacl.encoding.RawEncoder)
            box = nacl.secret.SecretBox(key)
            encoded_plaintext = box.decrypt(bytes.fromhex(encrypted_message.enc))
        except nacl.exceptions.CryptoError as e:
            raise ThresholdCryptoError('Message decryption failed. Internal: ' + str(e))

        return str(encoded_plaintext, 'utf-8')

    @staticmethod
    def _combine_shares(partial_decryptions: [PartialDecryption],
                       encrypted_message: EncryptedMessage,
                       threshold_params: ThresholdParameters,
                       key_params: KeyParameters
                       ) -> int:
        # Disabled to enable testing for unsuccessful decryption
        # if len(partial_decryptions) < threshold_params.t:
        #    raise ThresholdCryptoError('less than t partial decryptions given')

        # compute lagrange coefficients
        partial_indices = [dec.x for dec in partial_decryptions]
        lagrange_coefficients = number.build_lagrange_coefficients(partial_indices, key_params.q)

        factors = [
            pow(partial_decryptions[i].v_y, lagrange_coefficients[i], key_params.p)
            for i in range(0, len(partial_decryptions))
        ]
        restored_g_ka = number.prod(factors) % key_params.p
        restored_g_minus_ak = number.prime_mod_inv(restored_g_ka, key_params.p)
        restored_m = encrypted_message.c * restored_g_minus_ak % key_params.p

        return restored_m

