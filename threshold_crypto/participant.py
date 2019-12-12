from threshold_crypto.data import EncryptedMessage, KeyShare, PartialDecryption, PartialReEncryptionKey


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


def compute_partial_re_encryption_key(old_share: KeyShare, old_lambda: int, new_share: KeyShare, new_lambda: int) -> PartialReEncryptionKey:
    """
    TBD
    """
    pass