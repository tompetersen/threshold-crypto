import nacl.utils
import nacl.secret
import nacl.encoding
import nacl.exceptions
import nacl.hash
from threshold_crypto.data import KeyParameters, ThresholdParameters, PublicKey, KeyShare, PartialDecryption, \
    EncryptedMessage, ThresholdCryptoError, PartialReEncryptionKey, ReEncryptionKey
from threshold_crypto import number, Participant



# key generation


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


def create_public_key(participants_h_i: [int], key_params: KeyParameters, threshold_params: ThresholdParameters) -> PublicKey:
    """
    Pedersen91-related

    :param participants:
    :param key_params:
    :return:
    """
    if len(participants_h_i) != threshold_params.n:
        raise ThresholdCryptoError('number of participants h_i values {} != {} = n'.format(len(participants_h_i), threshold_params.n))

    h = number.prod(participants_h_i) % key_params.p
    return PublicKey(h, key_params)


def restore_priv_key(key_params: KeyParameters, shares: [KeyShare], treshold_params: ThresholdParameters):
    """
    Combine multiple key shares to compute the (implicit) private key.
    Just used for testing purposes - should never be used in a real scenario, if you don't have a special reason for this!

    :param key_params:
    :param shares:
    :param treshold_params:
    :return:
    """
    used_shares = shares[:treshold_params.t]
    x_shares = [share.x for share in used_shares]
    y_shares = [share.y for share in used_shares]

    lagrange_coefficients = number.build_lagrange_coefficients(x_shares, key_params.q)

    restored_a = sum([(lagrange_coefficients[i] * y_shares[i]) for i in range(0, len(used_shares))]) % key_params.q

    return restored_a


# encryption


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
    g_k, c = _encrypt_key_element(key_subgroup_element, public_key)

    return EncryptedMessage(g_k, c, encrypted)


def _encrypt_key_element(key_element: int, public_key: PublicKey) -> (int, int):
    key_params = public_key.key_parameters

    if key_element >= key_params.p:
        raise ThresholdCryptoError('key element is larger than key parameter p')

    k = number.getRandomRange(1, key_params.q - 1)
    g_k = pow(key_params.g, k, key_params.p)  # aka v
    g_ak = pow(public_key.g_a, k, key_params.p)
    c = (key_element * g_ak) % key_params.p

    return g_k, c


# decryption


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
    key_subgroup_element = _combine_shares(
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
