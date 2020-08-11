
from Crypto.PublicKey import ECC

from threshold_crypto.data import EncryptedMessage, KeyShare, PartialDecryption, PartialReEncryptionKey, \
    ThresholdCryptoError, CurveParameters, ThresholdParameters
from threshold_crypto import number


def compute_partial_decryption(encrypted_message: EncryptedMessage, key_share: KeyShare) -> PartialDecryption:
    """
    Compute the partial decryption of an encrypted message using a key share.

    :param encrypted_message: the encrypted message
    :param key_share: the key share
    :return: a partial decryption
    """
    yC1 = encrypted_message.C1 * key_share.y

    return PartialDecryption(key_share.x, yC1, key_share.curve_params)


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

    TODO
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

    tmp = [(- x(j) * number.prime_mod_inv(x(i) - x(j), key_params.q)) for j in range(0, k_tmp) if not j == i]
    return number.prod(tmp) % key_params.q  # lambda_i


class Participant:
    """

    """

    def __init__(self, node_id: int, key_params: KeyParameters, threshold_params: ThresholdParameters):
        """


        :param node_id:
        :param key_params:
        :param threshold_params:
        """
        self.a_i = number.getRandomRange(0, key_params.q - 1)  # Pedersen91 x_i from Z_q
        self.h_i = pow(key_params.g, self.a_i, key_params.p)
        self.node_id = node_id
        self.key_params = key_params
        self.threshold_params = threshold_params

        self._polynom = number.PolynomMod.create_random_polynom(self.a_i, self.threshold_params.t - 1, self.key_params.q)
        self._local_F_ij = []
        for coeff in self._polynom.coefficients:
            self._local_F_ij.append(pow(self.key_params.g, coeff, self.key_params.p))

        self._local_sij = {}
        self._received_F = {}  # received F_ij values from all participants
        self._received_sij = {}  # received s_ij values from all participants

        self.s_i = 0
        self.key_share = None

    def __str__(self):
        return "Participant[node_id = {}, a_i = {}, h_i = {}, s_i = {}".format(self.node_id, self.a_i, self.h_i, self.s_i)

    def receive_F(self, node_id: int, node_F_ij: [int]):
        if len(node_F_ij) != self.threshold_params.t:
            raise ThresholdCryptoError("list of F_ij for node {} has length {} != {} = t".format(node_id, len(node_F_ij), self.threshold_params.t))

        if node_id not in self._received_F:
            self._received_F[node_id] = node_F_ij
        else:
            raise ThresholdCryptoError("F value for node {} already received".format(node_id))

    def calculate_sij(self, node_id_list: [int]):
        if len(node_id_list) != self.threshold_params.n:
            raise ThresholdCryptoError("list of node ids has length {} != {} = n".format(len(node_id_list), self.threshold_params.n))

        for node_id in node_id_list:
            s_ij = self._polynom.evaluate(node_id)
            self._local_sij[node_id] = s_ij

    def receive_sij(self, node_id: int, received_sij: int):
        if node_id not in self._received_sij:
            self._received_sij[node_id] = received_sij
        else:
            raise ThresholdCryptoError("s_ij value for node {} already received".format(node_id))

        # verify received F values
        g_s_ij = pow(self.key_params.g, received_sij, self.key_params.p)
        F_list = [(F_jl ** (self.node_id ** l)) for l, F_jl in enumerate(self._received_F[node_id])]
        F_product = number.prod(F_list) % self.key_params.p

        if g_s_ij != F_product:
            raise ThresholdCryptoError("F verification failed for node {}".format(node_id))

    def compute_share(self):
        if len(self._received_sij) != self.threshold_params.n:
            raise ThresholdCryptoError("received less sij values than necessary: {} != {} = n".format(len(self._received_sij), self.threshold_params.t))

        self.s_i = sum(self._received_sij.values()) % self.key_params.q
        self.key_share = KeyShare(self.node_id, self.s_i, self.key_params)

