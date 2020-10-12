from typing import Dict, List, Optional

from Crypto.PublicKey import ECC
from Crypto.Random import random
from Crypto.Hash import SHA3_256

from threshold_crypto.data import EncryptedMessage, KeyShare, PartialDecryption, PartialReEncryptionKey, \
    ThresholdCryptoError, CurveParameters, ThresholdParameters, LagrangeCoefficient, DkgClosedCommitment, DkgOpenCommitment, DkgSijValue, DkgFijValue
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


def compute_partial_re_encryption_key(old_share: KeyShare, old_lc: LagrangeCoefficient, new_share: KeyShare, new_lc: LagrangeCoefficient) -> PartialReEncryptionKey:
    """
    Compute a partial re-encryption key from a participants old and new share.

    :param old_share:
    :param old_lc:
    :param new_share:
    :param new_lc:
    :return:
    """
    curve_params = old_share.curve_params

    if curve_params != new_share.curve_params:
        raise ThresholdCryptoError('Differing curves not supported for re-encryption!')

    if old_share.x != old_lc.participant_index:
        raise ThresholdCryptoError('Lagrange coefficient for OLD share was computed for other participant index')

    if new_share.x != new_lc.participant_index:
        raise ThresholdCryptoError('Lagrange coefficient for NEW share was computed for other participant index')

    partial_re_key = (new_share.y * new_lc.coefficient - old_share.y * old_lc.coefficient) % curve_params.order

    return PartialReEncryptionKey(partial_re_key, curve_params)


class Participant:
    """

    """

    def __init__(self, node_id: int, curve_params: CurveParameters, threshold_params: ThresholdParameters):
        """


        :param node_id:
        :param key_params:
        :param threshold_params:
        """
        self.x_i = number.random_in_range(0, curve_params.order)  # Pedersen91 x_i from Z_q
        self.h_i = self.x_i * curve_params.P
        self.node_id = node_id
        self.curve_params = curve_params
        self.threshold_params = threshold_params

        self._polynom = number.PolynomMod.create_random_polynom(self.x_i, self.threshold_params.t - 1, curve_params.order)
        self._local_F_ij = []
        for coeff in self._polynom.coefficients:
            self._local_F_ij.append(coeff * curve_params.P)

        self._local_sij = {}
        self._received_F = {}  # received F_ij values from all participants
        self._received_sij = {}  # received s_ij values from all participants

        self.s_i = 0
        self.key_share = None

    @staticmethod
    def _compute_commitment(commitment_random: bytes, h_i: ECC.EccPoint):
        hash_fct = SHA3_256.new(commitment_random)
        hash_fct.update(bytes(h_i.x))
        hash_fct.update(bytes(h_i.y))
        return hash_fct.digest()

    def closed_commmitment(self) -> DkgClosedCommitment:
        return DkgClosedCommitment(self.node_id, self._commitment)

    def receive_closed_commitment(self, commitment: DkgClosedCommitment):
        source_id = commitment.node_id

        if source_id not in self.all_node_ids:
            raise ThresholdCryptoError("Received closed commitment from unknown node id {}".format(source_id))

        if source_id not in self._received_closed_commitments:
            self._received_closed_commitments[source_id] = commitment
        else:
            raise ThresholdCryptoError("Closed commitment from node {} already received".format(source_id))

    def open_commitment(self) -> DkgOpenCommitment:
        if len(self._received_closed_commitments) != self.threshold_params.n - 1:
            raise ThresholdCryptoError(
                "Open commitment is just accessible when all other closed commitments were received")

        return DkgOpenCommitment(self.node_id, self._commitment, self.h_i, self._commitment_random)

    def receive_open_commitment(self, commitment: DkgOpenCommitment):
        source_id = commitment.node_id

        if source_id not in self.all_node_ids:
            raise ThresholdCryptoError("Received open commitment from unknown node id {}".format(source_id))

        if source_id not in self._received_open_commitments:
            self._received_open_commitments[source_id] = commitment
        else:
            raise ThresholdCryptoError("Open commitment from node {} already received".format(source_id))

    def _check_commitment_validity(self):
        if len(self._received_closed_commitments) != self.threshold_params.n - 1:
            raise ThresholdCryptoError("Not all commitments were received")

        for node_id in self._received_closed_commitments:
            closed_commitment = self._received_closed_commitments[node_id]
            open_commitment = self._received_open_commitments[node_id]

            if closed_commitment.commitment != open_commitment.commitment:
                raise ThresholdCryptoError("Open and close commitment values differ for node {}".format(node_id))

            if self._compute_commitment(open_commitment.r, open_commitment.h_i) != closed_commitment.commitment:
                raise ThresholdCryptoError("Invalid commitment for node {}".format(node_id))

    def receive_F(self, node_id: int, node_F_ij: [ECC.EccPoint]):
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
        s_ijP = received_sij * self.curve_params.P
        F_list = [(self.node_id ** l) * F_jl for l, F_jl in enumerate(self._received_F[node_id])]
        F_sum = number.ecc_sum(F_list)

        if s_ijP != F_sum:
            raise ThresholdCryptoError("F verification failed for node {}".format(node_id))

    def compute_share(self) -> KeyShare:
        """
        Compute the participants key share from values obtained during the DKG protocol.

        :return: the final key share after the DKG protocol
        """
        if len(self._received_sij) != self.threshold_params.n:
            raise ThresholdCryptoError("Received less s_ij values than necessary: {} != {} = n".format(len(self._received_sij), self.threshold_params.n))

        self.s_i = sum(self._received_sij.values()) % self.curve_params.order
        self.key_share = KeyShare(self.node_id, self.s_i, self.curve_params)

        return self.key_share

    def __str__(self):
        return "Participant[node_id = {}, a_i = {}, h_i = {}, s_i = {}".format(self.node_id, self.x_i, self.h_i, self.s_i)