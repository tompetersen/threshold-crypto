from threshold_crypto.data import EncryptedMessage, KeyShare, PartialDecryption, PartialReEncryptionKey, \
    ThresholdCryptoError
from threshold_crypto.number import prime_mod_inv, prod


def compute_partial_decryption(encrypted_message: EncryptedMessage, key_share: KeyShare) -> PartialDecryption:
    """
    Compute the partial decryption of an encrypted message using a key share.

    :param encrypted_message: the encrypted message
    :param key_share: the key share
    :return: a partial decryption
    """
    key_params = key_share.key_parameters

    v_y = pow(encrypted_message.v, key_share.y, key_params.p)

    return PartialDecryption(key_share.x, v_y)


def compute_partial_re_encryption_key(old_share: KeyShare, old_lambda: int, new_share: KeyShare, new_lambda: int) -> PartialReEncryptionKey:
    """
    Compute a partial re-encryption key from a participants old and new share.

    :param old_share:
    :param old_lambda:
    :param new_share:
    :param new_lambda:
    :return:
    """
    if old_share.key_parameters != new_share.key_parameters:
        raise ThresholdCryptoError("Key parameters in old and new share differ")

    key_params = new_share.key_parameters
    partial_re_key = (new_share.y * new_lambda - old_share.y * old_lambda) % key_params.q

    return PartialReEncryptionKey(partial_re_key, key_params)


def _compute_lagrange_coefficient_for_key_shares(key_shares: [KeyShare], i: int) -> int:
    """
    Create the ith Lagrange coefficient for a list of key shares.

    Just temporary! This will live in a centralized spot later so that participants just receive the coefficient later.
    It will obviously just take the x-values into account.

    :param key_shares:
    :param i:
    :return:
    """
    x_values = [share.x for share in key_shares]
    key_params = key_shares[0].key_parameters
    k_tmp = len(x_values)

    def x(idx):
        return x_values[idx]

    tmp = [(- x(j) * prime_mod_inv(x(i) - x(j), key_params.q)) for j in range(0, k_tmp) if not j == i]
    return prod(tmp) % key_params.q  # lambda_i
