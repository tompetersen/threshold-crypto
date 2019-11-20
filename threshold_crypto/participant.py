from threshold_crypto.data import EncryptedMessage, KeyShare, PartialDecryption


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

