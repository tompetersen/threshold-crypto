import nacl.utils
import nacl.secret
import nacl.encoding
import nacl.exceptions
import nacl.hash
from Crypto.PublicKey import ECC

from threshold_crypto.data import CurveParameters, ThresholdParameters, KeyShare, PartialDecryption, \
    EncryptedMessage, ThresholdCryptoError, PartialReEncryptionKey, ReEncryptionKey, PublicKey
from threshold_crypto import number


# key generation


def create_public_key_and_shares_centralized(curve_params: CurveParameters, threshold_params: ThresholdParameters) -> (ECC.EccPoint, [KeyShare]):
    """
    Creates a public key and n shares by choosing a random secret key and using it for computations.

    :param curve_params: curve parameters to use
    :param threshold_params: parameters t and n for the threshold scheme
    :return: (the public key, n key shares)
    """
    d = number.getRandomRange(1, curve_params.order)
    Q = d * curve_params.P
    pk = PublicKey(Q, curve_params)

    # Perform Shamir's secret sharing in Z_q
    polynom = number.PolynomMod.create_random_polynom(d, threshold_params.t - 1, curve_params.order)
    supporting_points = range(1, threshold_params.n + 1)
    shares = [KeyShare(x, polynom.evaluate(x), curve_params) for x in supporting_points]

    return pk,shares


def create_public_key(participants_h_i: [ECC.EccPoint], curve_parameters: CurveParameters, threshold_params: ThresholdParameters) -> PublicKey:
    """
    Pedersen91-related

    :param participants:
    :param key_params:
    :return:
    """
    if len(participants_h_i) != threshold_params.n:
        raise ThresholdCryptoError('number of participants h_i values {} != {} = n'.format(len(participants_h_i), threshold_params.n))

    h = number.ecc_sum(participants_h_i)

    return PublicKey(h, curve_parameters)


def restore_priv_key(curve_params: CurveParameters, shares: [KeyShare], treshold_params: ThresholdParameters):
    """
    Combine multiple key shares to compute the (implicit) private key.

    ATTENTION: Just used for testing purposes - should never be used in a real scenario, if you don't have a special reason for this!

    :param key_params:
    :param shares:
    :param treshold_params:
    :return:
    """
    used_shares = shares[:treshold_params.t]
    x_shares = [share.x for share in used_shares]
    y_shares = [share.y for share in used_shares]

    lagrange_coefficients = number.build_lagrange_coefficients(x_shares, curve_params.order)

    restored_secret = sum([(lagrange_coefficients[i] * y_shares[i]) for i in range(0, len(used_shares))]) % curve_params.order

    return restored_secret


# encryption


def encrypt_message(message: str, public_key: PublicKey) -> EncryptedMessage:
    """
    Encrypt a message using a public key. A hybrid encryption approach is used to include advantages of symmetric
    encryption (fast, independent of message-length, integrity-preserving by using AE-scheme).
    Internally a combination of Salsa20 and Poly1305 from the cryptographic library NaCl is used.

    :param message: the message to be encrypted
    :param public_key: the public key
    :return: the encrypted message
    """
    curve_params = public_key.curve_params
    encoded_message = bytes(message, 'utf-8')

    # Create random subgroup element and use its hash as symmetric key to prevent
    # attacks described in "Why Textbook ElGamal and RSA Encryption Are Insecure"
    # by Boneh et. al.
    r = number.getRandomRange(1, curve_params.order)
    key_point = r * curve_params.P
    point_bytes = _key_bytes_from_point(key_point)

    try:
        symmetric_key = nacl.hash.blake2b(point_bytes,
                                          digest_size=nacl.secret.SecretBox.KEY_SIZE,
                                          encoder=nacl.encoding.RawEncoder)
        # Use derived symmetric key to encrypt the message
        box = nacl.secret.SecretBox(symmetric_key)
        encrypted = box.encrypt(encoded_message)
    except nacl.exceptions.CryptoError as e:
        print('Encryption failed: ' + str(e))
        raise ThresholdCryptoError('Message encryption failed.')

    # Use threshold scheme to encrypt the curve point used as hash input to derive the symmetric key
    C1, C2 = _encrypt_key_point(key_point, public_key.Q, curve_params)

    return EncryptedMessage(C1, C2, encrypted)


def _key_bytes_from_point(p: ECC.EccPoint) -> bytes:
    key_point_byte_length = (int(p.x).bit_length() + 7) // 8
    point_bytes = int(p.x).to_bytes(key_point_byte_length, byteorder='big')
    return point_bytes


def _encrypt_key_point(key_point: ECC.EccPoint, Q: ECC.EccPoint, curve_params: CurveParameters) -> (ECC.EccPoint, ECC.EccPoint):
    k = number.getRandomRange(1, curve_params.order)
    C1 = k * curve_params.P
    kQ = k * Q
    C2 = key_point + kQ

    return C1, C2


# decryption


def decrypt_message(partial_decryptions: [PartialDecryption],
                    encrypted_message: EncryptedMessage,
                    threshold_params: ThresholdParameters
                    ) -> str:
    """
    Decrypt a message using the combination of at least t partial decryptions. Similar to the encryption process
    the hybrid approach is used for decryption.

    :param partial_decryptions: at least t partial decryptions
    :param encrypted_message: the encrapted message to be decrypted
    :param threshold_params: the used threshold parameters
    :param curve_params: the used curve parameters
    :return: the decrypted message
    """
    curve_params = partial_decryptions[0].curve_params
    for partial_key in partial_decryptions:
        if partial_key.curve_params != curve_params:
            raise ThresholdCryptoError("Varying curve parameters found in partial re-encryption keys")

    key_point = _combine_shares(
        partial_decryptions,
        encrypted_message,
        threshold_params,
        curve_params
    )
    point_bytes = _key_bytes_from_point(key_point)

    try:
        key = nacl.hash.blake2b(point_bytes,
                                digest_size=nacl.secret.SecretBox.KEY_SIZE,
                                encoder=nacl.encoding.RawEncoder)
        box = nacl.secret.SecretBox(key)
        encoded_plaintext = box.decrypt(encrypted_message.ciphertext)
    except nacl.exceptions.CryptoError as e:
        raise ThresholdCryptoError('Message decryption failed. Internal: ' + str(e))

    return str(encoded_plaintext, 'utf-8')


def _combine_shares(partial_decryptions: [PartialDecryption],
                   encrypted_message: EncryptedMessage,
                   threshold_params: ThresholdParameters,
                   curve_params: CurveParameters
                   ) -> ECC.EccPoint:
    # Disabled to enable testing for unsuccessful decryption
    # if len(partial_decryptions) < threshold_params.t:
    #    raise ThresholdCryptoError('less than t partial decryptions given')

    # compute lagrange coefficients
    partial_indices = [dec.x for dec in partial_decryptions]
    lagrange_coefficients = number.build_lagrange_coefficients(partial_indices, curve_params.order)

    summands = [lagrange_coefficients[i] * partial_decryptions[i].yC1 for i in range(0, len(partial_decryptions))]
    restored_kdP = number.ecc_sum(summands)

    restored_point = encrypted_message.C2 + (-restored_kdP)

    return restored_point


# re-encryption


def combine_partial_re_encryption_keys(partial_keys: [PartialReEncryptionKey], old_threshold_params: ThresholdParameters, new_threshold_params: ThresholdParameters) -> ReEncryptionKey:
    """
    TBD
    """
    # TODO check threshold parameters
    if old_threshold_params != new_threshold_params:
        raise ThresholdCryptoError("Threshold parameters differ! For now this is not allowed...")

    if len(partial_keys) < new_threshold_params.t or len(partial_keys) < 1:
        raise ThresholdCryptoError("Not enough partial re-encryption keys given")

    key_params = partial_keys[0].key_params
    for partial_key in partial_keys:
        if partial_key.key_params != key_params:
            raise ThresholdCryptoError("Varying key params found in partial re-encryption keys")

    re_key = sum([k.partial_key for k in partial_keys]) % key_params.q

    return ReEncryptionKey(re_key, key_params)


def re_encrypt_message(em: EncryptedMessage, re_key: ReEncryptionKey) -> EncryptedMessage:
    """
    TBD
    :param em:
    :param re_key:
    :return:
    """
    p = re_key.key_params.p
    re_enc_c = em.c * pow(em.v, re_key.key, p) % p

    return EncryptedMessage(em.v, re_enc_c, em.enc)
