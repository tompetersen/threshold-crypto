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

    :param old_share: the participants "old" key share
    :param old_lc: "old" lagrange coefficient provided by the coordinating party
    :param new_share: the participants "new" key share
    :param new_lc: "new" lagrange coefficient provided by the coordinating party
    :return: the partial re-encryption key
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
    A Participant provides the interface for a participant in the distributed key generation (DKG) protocol of Pedersen91.
    Required values for other participants can be obtained and functionality to receive these values is offered.
    A multitude of checks are performed to prevent illegal state or actions during the protocol. However, several communication
    aspects as e.g., the secure transport of s_ij values to other participants, are not included and have to be assured
    by users of this class.
    """

    _COMMITMENT_RANDOM_BITS = 256

    def __init__(self, own_id: ParticipantId, all_participant_ids: List[ParticipantId], curve_params: CurveParameters, threshold_params: ThresholdParameters):
        """
        Initialize a participant.

        :param own_id: the id of this participant.
        As this id is used as the final shares x value, it's important that participants use distinct ids.
        :param all_participant_ids: a list of all
        :param curve_params: the curve parameters used
        :param threshold_params: the required threshold parameters
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

        # random value for commitment of h_i
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
            self.id: self._unchecked_s_ij_value_for_participant(self.id)
        }

        self._s_i: Optional[int] = None
        self.key_share: Optional[KeyShare] = None

    @staticmethod
    def _compute_commitment(commitment_random: bytes, h_i: ECC.EccPoint):
        hash_fct = SHA3_256.new(commitment_random)
        hash_fct.update(number.int_to_bytes(int(h_i.x)))
        hash_fct.update(number.int_to_bytes(int(h_i.y)))
        return hash_fct.digest()

    def closed_commmitment(self) -> DkgClosedCommitment:
        """
        The participants closed commitment to the "public key share" h_i.

        :return: the closed commitment
        """
        return DkgClosedCommitment(self.id, self._commitment)

    def receive_closed_commitment(self, commitment: DkgClosedCommitment):
        """
        Receive a closed commitment to the "public key share" h_i of another participant.

        :param commitment: the received commitment
        """
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
        """
        The participants open commitment to the "public key share" h_i, which can be evaluated.

        :return: the open commitment
        """
        if len(self._received_closed_commitments) != self.threshold_params.n:
            raise ThresholdCryptoError(
                "Open commitment is just accessible when all other closed commitments were received")

        return self._unchecked_open_commitment()

    def _unchecked_open_commitment(self) -> DkgOpenCommitment:
        # This method is provided so that it can be used for the own commitment computation in the __init__
        # method without performing the check in open_commitment.
        return DkgOpenCommitment(self.id, self._commitment, self._h_i, self._commitment_random)

    def receive_open_commitment(self, open_commitment: DkgOpenCommitment):
        """
        Receive an open (evaluatable) commitment to the "public key share" h_i of another participant.

        :param open_commitment: the received commitment
        """
        source_id = open_commitment.participant_id

        if source_id not in self.all_participant_ids:
            raise ThresholdCryptoError("Received open commitment from unknown participant id {}".format(source_id))

        if source_id == self.id:
            raise ThresholdCryptoError("Received own open commitment - don't do this")

        if source_id not in self._received_closed_commitments:
            raise ThresholdCryptoError("Received open commitment from participant id {} withput received closed commitment".format(source_id))

        closed_commitment = self._received_closed_commitments[source_id]

        if closed_commitment.commitment != open_commitment.commitment:
            raise ThresholdCryptoError("Open and close commitment values differ for participant {}".format(source_id))

        if self._compute_commitment(open_commitment.r, open_commitment.h_i) != closed_commitment.commitment:
            raise ThresholdCryptoError("Invalid commitment for participant {}".format(source_id))

        if source_id not in self._received_open_commitments:
            self._received_open_commitments[source_id] = open_commitment
        else:
            raise ThresholdCryptoError("Open commitment from participant {} already received".format(source_id))

    def compute_public_key(self) -> PublicKey:
        """
        Compute the public key from received commitment values.

        :return: the public key
        """
        if len(self._received_open_commitments) != self.threshold_params.n:
            raise ThresholdCryptoError("Not all commitments were received")

        participants_h_i = [c.h_i for c in self._received_open_commitments.values()]
        h = number.ecc_sum(participants_h_i)

        return PublicKey(h, self.curve_params)

    def F_ij_value(self) -> DkgFijValue:
        """
        The F_ij value from Pedersens DKG protocol, which is used to evaluate the correctness of the s_ij
        values received in a later step.

        :return: The F_ij value
        """
        return DkgFijValue(self.id, self._local_F_ij)

    def receive_F_ij_value(self, F_ij: DkgFijValue):
        """
        Receive the F_ij value of another participant.

        :param F_ij: the received F_ij value
        """
        # implicit check for successful receival of all commitments
        self.compute_public_key()

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
        """
        The s_ij value from Pedersens DKG protocol for ONE other particular participant.
        This value has to be sent SECRETLY to the target participant, which is not covered by this library for now.

        :param target_participant_id: the id of the target participant
        """
        if len(self._received_F) != self.threshold_params.n:
            raise ThresholdCryptoError(
                "s_ij values are just accessible when all other F_ij values were received")

        return self._unchecked_s_ij_value_for_participant(target_participant_id)

    def _unchecked_s_ij_value_for_participant(self, target_participant_id: ParticipantId) -> DkgSijValue:
        # This method is provided so that it can be used for the own s_ij value computation in the __init__
        # method without performing the check in s_ij_value_for_participant.
        if target_participant_id not in self.all_participant_ids:
            raise ThresholdCryptoError("Participant id {} not present in known participant ids".format(target_participant_id))
        else:
            return DkgSijValue(self.id, target_participant_id, self._local_sij[target_participant_id])

    def receive_sij(self, received_sij: DkgSijValue):
        """
        Receive the s_ij value of another participant.

        :param received_sij: the received s_ij value
        """
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