from typing import Dict, List, Optional

from Crypto.PublicKey import ECC
from Crypto.Random import random
from Crypto.Hash import SHA3_256

from threshold_crypto.data import EncryptedMessage, KeyShare, PartialDecryption, PartialReEncryptionKey, \
    ThresholdCryptoError, CurveParameters, ThresholdParameters, LagrangeCoefficient, DkgClosedCommitment, \
    DkgOpenCommitment, DkgSijValue, DkgFijValue, PublicKey
from threshold_crypto import number

ParticipantId = int


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

    _COMMITMENT_RANDOM_BITS = 256

    def __init__(self, own_id: ParticipantId, all_participant_ids: List[ParticipantId], curve_params: CurveParameters, threshold_params: ThresholdParameters):
        """
        TODO

        :param key_params:
        :param own_id: the id of this participant.
        :param threshold_params:
        """
        if len(set(all_participant_ids)) != threshold_params.n:
            raise ThresholdCryptoError("List of distinct participant ids has length {} != {} = n".format(len(all_participant_ids), threshold_params.n))

        if own_id not in all_participant_ids:
            raise ThresholdCryptoError("Own id must be contained in all participant ids")

        self.all_participant_ids: List[ParticipantId] = all_participant_ids
        self.id: ParticipantId = own_id
        self.curve_params: CurveParameters = curve_params
        self.threshold_params: ThresholdParameters = threshold_params

        self._x_i: int = number.random_in_range(0, curve_params.order)
        self._h_i: ECC.EccPoint = self._x_i * curve_params.P
        self._polynom: number.PolynomMod = number.PolynomMod.create_random_polynom(self._x_i, self.threshold_params.t - 1, curve_params.order)

        # calculate own F_ij values
        self._local_F_ij: List[ECC.EccPoint] = []
        for coeff in self._polynom.coefficients:
            self._local_F_ij.append(coeff * curve_params.P)

        # calculate own s_ij values
        self._local_sij: Dict[ParticipantId, int] = {}
        for p_id in self.all_participant_ids:
            s_ij = self._polynom.evaluate(p_id)
            self._local_sij[p_id] = s_ij

        # random value for commitment for value h_i
        rand_int = random.getrandbits(self._COMMITMENT_RANDOM_BITS)
        self._commitment_random: bytes = number.int_to_bytes(rand_int)
        self._commitment: bytes = self._compute_commitment(self._commitment_random, self._h_i)

        self._received_closed_commitments: Dict[ParticipantId, DkgClosedCommitment] = {
            self.id: self.closed_commmitment()
        }
        self._received_open_commitments: Dict[ParticipantId, DkgOpenCommitment] = {
            self.id: self._unchecked_open_commitment()
        }
        self._received_F: Dict[ParticipantId, DkgFijValue] = {
            self.id: self.F_ij_value()
        }
        self._received_sij: Dict[ParticipantId, DkgSijValue] = {
            self.id: self.s_ij_value_for_participant(self.id)
        }

        self._s_i: int = 0
        self.key_share: Optional[KeyShare] = None

    @staticmethod
    def _compute_commitment(commitment_random: bytes, h_i: ECC.EccPoint):
        hash_fct = SHA3_256.new(commitment_random)
        hash_fct.update(number.int_to_bytes(int(h_i.x)))
        hash_fct.update(number.int_to_bytes(int(h_i.y)))
        return hash_fct.digest()

    def closed_commmitment(self) -> DkgClosedCommitment:
        return DkgClosedCommitment(self.id, self._commitment)

    def receive_closed_commitment(self, commitment: DkgClosedCommitment):
        source_id = commitment.participant_id

        if source_id not in self.all_participant_ids:
            raise ThresholdCryptoError("Received closed commitment from unknown participant id {}".format(source_id))

        if source_id == self.id:
            raise ThresholdCryptoError("Received own closed commitment - don't do this")

        if source_id not in self._received_closed_commitments:
            self._received_closed_commitments[source_id] = commitment
        else:
            raise ThresholdCryptoError("Closed commitment from participant {} already received".format(source_id))

    def open_commitment(self) -> DkgOpenCommitment:
        if len(self._received_closed_commitments) != self.threshold_params.n:
            raise ThresholdCryptoError(
                "Open commitment is just accessible when all other closed commitments were received")

        return self._unchecked_open_commitment()

    def _unchecked_open_commitment(self) -> DkgOpenCommitment:
        return DkgOpenCommitment(self.id, self._commitment, self._h_i, self._commitment_random)

    def receive_open_commitment(self, commitment: DkgOpenCommitment):
        source_id = commitment.participant_id

        if source_id not in self.all_participant_ids:
            raise ThresholdCryptoError("Received open commitment from unknown participant id {}".format(source_id))

        if source_id == self.id:
            raise ThresholdCryptoError("Received own open commitment - don't do this")

        if source_id not in self._received_open_commitments:
            self._received_open_commitments[source_id] = commitment
        else:
            raise ThresholdCryptoError("Open commitment from participant {} already received".format(source_id))

    def _check_all_commitment_validities(self):
        if len(self._received_closed_commitments) != self.threshold_params.n:
            raise ThresholdCryptoError("Not all commitments were received")

        for p_id in self._received_closed_commitments:
            closed_commitment = self._received_closed_commitments[p_id]
            open_commitment = self._received_open_commitments[p_id]

            if closed_commitment.commitment != open_commitment.commitment:
                raise ThresholdCryptoError("Open and close commitment values differ for participant {}".format(p_id))

            if self._compute_commitment(open_commitment.r, open_commitment.h_i) != closed_commitment.commitment:
                raise ThresholdCryptoError("Invalid commitment for participant {}".format(p_id))

    def computed_public_key(self) -> PublicKey:
        self._check_all_commitment_validities()

        participants_h_i = [c.h_i for c in self._received_open_commitments.values()]
        h = number.ecc_sum(participants_h_i)

        return PublicKey(h, self.curve_params)

    def F_ij_value(self) -> DkgFijValue:
        return DkgFijValue(self.id, self._local_F_ij)

    def receive_F_ij_value(self, F_ij: DkgFijValue):
        # TODO check that all commitments match once before receiving the first F_ij value (boolean flag/global state enum/...?)

        source_id = F_ij.source_participant_id
        len_F_ij = len(F_ij.F_ij)

        if source_id not in self.all_participant_ids:
            raise ThresholdCryptoError("Received F_ij values from unknown participant id {}".format(source_id))

        if source_id == self.id:
            raise ThresholdCryptoError("Received own F_ij values - don't do this")

        if len_F_ij != self.threshold_params.t:
            raise ThresholdCryptoError("List of F_ij values from participant {} has length {} != {} = t".format(source_id, len_F_ij, self.threshold_params.t))

        if source_id not in self._received_F:
            self._received_F[source_id] = F_ij
        else:
            raise ThresholdCryptoError("F_ij values from participant {} already received".format(source_id))

    def s_ij_value_for_participant(self, target_participant_id: ParticipantId) -> DkgSijValue:
        if target_participant_id not in self.all_participant_ids:
            raise ThresholdCryptoError("Participant id {} not present in known participant ids".format(target_participant_id))
        else:
            return DkgSijValue(self.id, target_participant_id, self._local_sij[target_participant_id])

    def receive_sij(self, received_sij: DkgSijValue):
        source_id = received_sij.source_participant_id
        target_id = received_sij.target_participant_id
        sij = received_sij.s_ij

        if source_id not in self.all_participant_ids:
            raise ThresholdCryptoError("Received s_ij value from unknown participant id {}".format(source_id))

        if source_id == self.id:
            raise ThresholdCryptoError("Received own s_ij value - don't do this")

        if target_id != self.id:
            raise ThresholdCryptoError("Received s_ij value for foreign participant (own id={}, target id={})".format(self.id, target_id))

        if source_id not in self._received_sij:
            self._received_sij[source_id] = received_sij
        else:
            raise ThresholdCryptoError("s_ij value for participant {} already received".format(source_id))

        # verify received F values
        s_ijP = sij * self.curve_params.P
        F_list = [(self.id ** l) * F_jl for l, F_jl in enumerate(self._received_F[source_id].F_ij)]
        F_sum = number.ecc_sum(F_list)

        if s_ijP != F_sum:
            raise ThresholdCryptoError("F verification failed for participant {}".format(source_id))

    def compute_share(self) -> KeyShare:
        """
        Compute the participants key share from values obtained during the DKG protocol.

        :return: the final key share after the DKG protocol
        """
        if len(self._received_sij) != self.threshold_params.n:
            raise ThresholdCryptoError("Received less s_ij values than necessary: {} != {} = n".format(len(self._received_sij), self.threshold_params.n))

        self._s_i = sum(rs.s_ij for rs in self._received_sij.values()) % self.curve_params.order
        self.key_share = KeyShare(self.id, self._s_i, self.curve_params)

        return self.key_share

    def __str__(self):
        return "Participant[id = {}, x_i = {}, h_i = {}, s_i = {}".format(self.id, self._x_i, self._h_i, self._s_i)