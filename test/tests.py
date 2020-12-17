import unittest

from Crypto.Random import random

from threshold_crypto.data import (ThresholdParameters,
                                   CurveParameters,
                                   ThresholdCryptoError,
                                   KeyShare,
                                   EncryptedMessage,
                                   PartialDecryption,
                                   PartialReEncryptionKey,
                                   ReEncryptionKey,
                                   PublicKey,
                                   DkgOpenCommitment,
                                   DkgSijValue,
                                   DkgClosedCommitment,
                                   DkgFijValue
                                   )
from threshold_crypto import number
from threshold_crypto import central
from threshold_crypto import participant


class TCTestCase(unittest.TestCase):

    def setUp(self):
        self.tp = ThresholdParameters(3, 5)
        self.cp = CurveParameters()
        self.pk, self.shares = central.create_public_key_and_shares_centralized(self.cp, self.tp)
        self.message = 'Some secret message'
        self.em = central.encrypt_message(self.message, self.pk)
        self.reconstruct_shares = [self.shares[i] for i in [0, 2, 4]]  # choose 3 of 5 key shares
        self.partial_decryptions = [participant.compute_partial_decryption(self.em, share) for share in self.reconstruct_shares]

    def tearDown(self):
        pass

    def test_valid_threshold_parameters(self):
        self.assertTrue(ThresholdParameters(3, 5))

    def test_invalid_threshold_parameters(self):
        with self.assertRaises(ThresholdCryptoError):
            ThresholdParameters(5, 3)

    def test_threshold_parameter_json(self):
        t = ThresholdParameters(3, 5)
        t_j = ThresholdParameters.from_json(t.to_json())

        self.assertEqual(t, t_j)

    def test_valid_curve_parameters(self):
        cp = CurveParameters()
        self.assertTrue(cp.order > 0)

    def test_invalid_curve_parameters_whole_group(self):
        with self.assertRaises(ThresholdCryptoError):
            CurveParameters(curve_name="invalid-curve")

    def test_curve_parameter_json(self):
        cp = CurveParameters()
        cp_j = CurveParameters.from_json(cp.to_json())

        self.assertEqual(cp, cp_j)

    def test_central_key_generation(self):
        pk, shares = central.create_public_key_and_shares_centralized(self.cp, self.tp)

        self.assertEqual(len(shares), self.tp.n)

    def test_public_key_json(self):
        pk_j = PublicKey.from_json(self.pk.to_json())

        self.assertEqual(self.pk, pk_j)

    def test_key_share_json(self):
        share = self.shares[0]
        share_j = KeyShare.from_json(share.to_json())

        self.assertEqual(share, share_j)

    def test_message_encryption(self):
        em = central.encrypt_message(self.message, self.pk)

        self.assertTrue(em.C1)
        self.assertTrue(em.C2)
        self.assertTrue(em.ciphertext)

    def test_message_json(self):
        m_j = EncryptedMessage.from_json(self.em.to_json())

        self.assertEqual(self.em, m_j)

    def test_partial_decryption_json(self):
        pd = self.partial_decryptions[0]
        pd_j = PartialDecryption.from_json(pd.to_json())

        self.assertEqual(pd, pd_j)

    # TBD: further tests

    def test_polynom_creation(self):
        p = number.PolynomMod.create_random_polynom(17, 5, 41)

        self.assertTrue(p.degree == 5)
        self.assertTrue(p.evaluate(0) == 17)

    def test_key_encryption_decryption_with_enough_shares(self):
        r = number.random_in_range(2, self.cp.order)
        testkey_element = r * self.cp.P
        kP, c = central._encrypt_key_point(testkey_element, self.pk.Q, self.cp)
        em = EncryptedMessage(kP, c, b'')
        reconstruct_shares = [self.shares[i] for i in [0, 2, 4]]  # choose 3 of 5 key shares
        partial_decryptions = [participant.compute_partial_decryption(em, share) for share in reconstruct_shares]
        rec_testkey_element = central._combine_shares(partial_decryptions, em, self.cp)

        self.assertEqual(testkey_element, rec_testkey_element)

    def test_key_encryption_decryption_without_enough_shares(self):
        r = number.random_in_range(2, self.cp.order)
        testkey_element = r * self.cp.P
        kP, c = central._encrypt_key_point(testkey_element, self.pk.Q, self.cp)
        em = EncryptedMessage(kP, c, b'')
        reconstruct_shares = [self.shares[i] for i in [0, 4]]  # choose 2 of 5 key shares
        partial_decryptions = [participant.compute_partial_decryption(em, share) for share in reconstruct_shares]
        rec_testkey_element = central._combine_shares(partial_decryptions, em, self.cp)

        self.assertNotEqual(testkey_element, rec_testkey_element)

    def test_complete_process_with_enough_shares(self):
        curve_params = CurveParameters()
        thresh_params = ThresholdParameters(3, 5)

        pub_key, key_shares = central.create_public_key_and_shares_centralized(curve_params, thresh_params)

        message = 'Some secret message to be encrypted!'
        encrypted_message = central.encrypt_message(message, pub_key)

        reconstruct_shares = [key_shares[i] for i in [0, 2, 4]]  # choose 3 of 5 key shares
        partial_decryptions = [participant.compute_partial_decryption(encrypted_message, share) for share in reconstruct_shares]
        decrypted_message = central.decrypt_message(partial_decryptions, encrypted_message, thresh_params)

        self.assertEqual(message, decrypted_message)

    def test_complete_process_without_enough_shares(self):
        curve_params = CurveParameters()
        thresh_params = ThresholdParameters(3, 5)

        pub_key, key_shares = central.create_public_key_and_shares_centralized(curve_params, thresh_params)

        message = 'Some secret message to be encrypted!'
        encrypted_message = central.encrypt_message(message, pub_key)

        reconstruct_shares = [key_shares[i] for i in [3, 4]]  # choose 2 of 5 key shares
        partial_decryptions = [participant.compute_partial_decryption(encrypted_message, share) for share in reconstruct_shares]

        with self.assertRaises(ThresholdCryptoError):
            central.decrypt_message(partial_decryptions, encrypted_message, thresh_params)


class PreTestCase(unittest.TestCase):
    """
    Test cases for the proxy reencryption scheme.
    """

    def setUp(self):
        self.tp = ThresholdParameters(3, 5)
        self.cp = CurveParameters()
        self.pk, self.shares = central.create_public_key_and_shares_centralized(self.cp, self.tp)
        self.message = 'Some secret message'
        self.em = central.encrypt_message(self.message, self.pk)
        self.reconstruct_shares = [self.shares[i] for i in [0, 2, 4]]  # choose 3 of 5 key shares
        self.partial_decryptions = [participant.compute_partial_decryption(self.em, share) for share in
                                    self.reconstruct_shares]

    def tearDown(self):
        pass

    def test_partial_re_encryption_key_json(self):
        prek = PartialReEncryptionKey(partial_key=17, curve_params=self.cp)
        prek_j = PartialReEncryptionKey.from_json(prek.to_json())

        self.assertEqual(prek, prek_j)

    def test_re_encryption_key_json(self):
        rek = ReEncryptionKey(key=42, curve_params=CurveParameters())
        rek_j = ReEncryptionKey.from_json(rek.to_json())

        self.assertEqual(rek, rek_j)

    def test_re_encryption_process_for_same_access_structures(self):
        self.parameterizable_re_encryption_process_test(self.tp.t, self.tp.n)

    def test_re_encryption_process_for_added_participant(self):
        self.parameterizable_re_encryption_process_test(self.tp.t, self.tp.n + 1)

    def test_re_encryption_process_for_removed_participant(self):
        self.parameterizable_re_encryption_process_test(self.tp.t, self.tp.n - 1)

    def test_re_encryption_process_for_smaller_threshold(self):
        self.parameterizable_re_encryption_process_test(self.tp.t - 1, self.tp.n)

    def test_re_encryption_process_for_larger_threshold(self):
        self.parameterizable_re_encryption_process_test(self.tp.t + 1, self.tp.n)

    def parameterizable_re_encryption_process_test(self, new_t: int, new_n: int):
        new_tp = ThresholdParameters(new_t, new_n)
        new_pk, new_shares = central.create_public_key_and_shares_centralized(self.cp, new_tp)

        assert new_pk != self.pk, "Public keys for new and old access structure are the same"

        # Without loss of generality we assume the lists to be ordered in a way, that remaining participants
        # are placed at the beginning of the list.
        # Choose t_max shares randomly from first min_n old and new shares as the shares of one distinct participant.
        max_t = max(self.tp.t, new_tp.t)
        min_n = min(self.tp.n, new_tp.n)
        t_old_shares = random.sample(self.shares[:min_n], k=max_t)
        t_old_shares_x = [share.x for share in t_old_shares]
        t_new_shares = random.sample(new_shares[:min_n], k=max_t)
        t_new_shares_x = [share.x for share in t_new_shares]

        partial_re_encrypt_keys = []
        for i, (s_old, s_new) in enumerate(zip(t_old_shares, t_new_shares)):
            old_lambda = central.lagrange_coefficient_for_key_share_indices(t_old_shares_x, t_old_shares_x[i], self.cp)
            new_lambda = central.lagrange_coefficient_for_key_share_indices(t_new_shares_x, t_new_shares_x[i], self.cp)
            partial_key = participant.compute_partial_re_encryption_key(s_old, old_lambda, s_new, new_lambda)
            partial_re_encrypt_keys.append(partial_key)

        re_encrypt_key = central.combine_partial_re_encryption_keys(partial_re_encrypt_keys,
                                                                    self.pk,
                                                                    new_pk,
                                                                    self.tp,
                                                                    new_tp)
        re_em = central.re_encrypt_message(self.em, re_encrypt_key)

        self.assertNotEqual(self.em, re_em)

        # successful decryption with t shares
        new_reconstruct_shares = random.sample(new_shares, new_tp.t)
        new_partial_decryptions = [participant.compute_partial_decryption(re_em, share) for share in new_reconstruct_shares]

        decrypted_message = central.decrypt_message(new_partial_decryptions, re_em, new_tp)
        self.assertEqual(self.message, decrypted_message)

        # failing decryption with t - 1 shares
        with self.assertRaises(ThresholdCryptoError) as dec_exception_context:
            less_reconstruct_shares = random.sample(new_shares, new_tp.t - 1)
            new_partial_decryptions = [participant.compute_partial_decryption(re_em, share) for share in less_reconstruct_shares]
            central._decrypt_message(new_partial_decryptions, re_em)

        self.assertIn("Message decryption failed", str(dec_exception_context.exception))


class DkgTestCase(unittest.TestCase):
    """
    Test cases for the distributed key generation.
    """

    def setUp(self):
        self.tp = ThresholdParameters(3, 5)
        self.cp = CurveParameters()
        self.message = 'Some secret message'

    def tearDown(self):
        pass

    def test_closed_commitment_json(self):
        c = DkgClosedCommitment(1, random.getrandbits(10))
        c_j = DkgClosedCommitment.from_json(c.to_json())

        self.assertEqual(c, c_j)

    def test_open_commitment_json(self):
        c = DkgOpenCommitment(1, random.getrandbits(10), self.cp.P, random.getrandbits(10))
        c_j = DkgOpenCommitment.from_json(c.to_json())

        self.assertEqual(c, c_j)

    def test_F_ij_value_json(self):
        f = DkgFijValue(1, [self.cp.P, 2 * self.cp.P])
        f_j = DkgFijValue.from_json(f.to_json())

        self.assertEqual(f, f_j)

    def test_s_ij_value_json(self):
        f = DkgSijValue(1, 2, 42)
        f_j = DkgSijValue.from_json(f.to_json())

        self.assertEqual(f, f_j)

    def test_distributed_key_generation(self):
        participant_ids = list(range(1, self.tp.n + 1))
        participants = [participant.Participant(id, participant_ids, self.cp, self.tp) for id in participant_ids]

        # via broadcast
        for pi in participants:
            for pj in participants:
                if pj != pi:
                    closed_commitment = pj.closed_commmitment()
                    pi.receive_closed_commitment(closed_commitment)

        # via broadcast
        for pi in participants:
            for pj in participants:
                if pj != pi:
                    open_commitment = pj.open_commitment()
                    pi.receive_open_commitment(open_commitment)

        public_key = participants[0].compute_public_key()
        for pk in [p.compute_public_key() for p in participants[1:]]:
            self.assertEqual(public_key, pk)

        # via broadcast
        for pi in participants:
            for pj in participants:
                if pj != pi:
                    F_ij = pj.F_ij_value()
                    pi.receive_F_ij_value(F_ij)

        # SECRETLY from i to j
        for pi in participants:
            for pj in participants:
                if pj != pi:
                    s_ij = pj.s_ij_value_for_participant(pi.id)
                    pi.receive_sij(s_ij)

        shares = [p.compute_share() for p in participants]

        # test encryption/decryption

        em = central.encrypt_message(self.message, public_key)

        pdms = [participant.compute_partial_decryption(em, ks) for ks in shares[:self.tp.t]]
        dm = central.decrypt_message(pdms, em, self.tp)

        self.assertEqual(dm, self.message)

    def test_compromised_open_commitment(self):
        participant_ids = list(range(1, self.tp.n + 1))
        participants = [participant.Participant(id, participant_ids, self.cp, self.tp) for id in participant_ids]

        # via broadcast
        for pi in participants:
            for pj in participants:
                if pj != pi:
                    closed_commitment = pj.closed_commmitment()
                    pi.receive_closed_commitment(closed_commitment)

        with self.assertRaises(ThresholdCryptoError):
            open_commitment = participants[0].open_commitment()

            # tamper with open commitment
            open_commitment.h_i = 2 * open_commitment.h_i

            participants[1].receive_open_commitment(open_commitment)

    def test_compromised_F_value(self):
        participant_ids = list(range(1, self.tp.n + 1))
        participants = [participant.Participant(id, participant_ids, self.cp, self.tp) for id in participant_ids]

        # via broadcast
        for pi in participants:
            for pj in participants:
                if pj != pi:
                    closed_commitment = pj.closed_commmitment()
                    pi.receive_closed_commitment(closed_commitment)

        # via broadcast
        for pi in participants:
            for pj in participants:
                if pj != pi:
                    open_commitment = pj.open_commitment()
                    pi.receive_open_commitment(open_commitment)

        # via broadcast
        for pi in participants:
            for pj in participants:
                if pj != pi:
                    F_ij = pj.F_ij_value()

                    # tamper with one F_ij
                    if pj.id == 1:
                        F_ij.F_ij[0] = 2 * F_ij.F_ij[0]

                    pi.receive_F_ij_value(F_ij)

        # SECRETLY from i to j
        with self.assertRaises(ThresholdCryptoError):
            s_ij = participants[0].s_ij_value_for_participant(participants[1].id)
            participants[1].receive_sij(s_ij)

    def test_compromised_s_ij_value(self):
        participant_ids = list(range(1, self.tp.n + 1))
        participants = [participant.Participant(id, participant_ids, self.cp, self.tp) for id in participant_ids]

        # via broadcast
        for pi in participants:
            for pj in participants:
                if pj != pi:
                    closed_commitment = pj.closed_commmitment()
                    pi.receive_closed_commitment(closed_commitment)

        # via broadcast
        for pi in participants:
            for pj in participants:
                if pj != pi:
                    open_commitment = pj.open_commitment()
                    pi.receive_open_commitment(open_commitment)

        # via broadcast
        for pi in participants:
            for pj in participants:
                if pj != pi:
                    F_ij = pj.F_ij_value()
                    pi.receive_F_ij_value(F_ij)

        # SECRETLY from i to j
        with self.assertRaises(ThresholdCryptoError):
            s_ij = participants[0].s_ij_value_for_participant(participants[1].id)

            # tamper with s_ij
            s_ij.s_ij = 2 * s_ij.s_ij % self.cp.order

            participants[1].receive_sij(s_ij)

    def test_not_enough_open_commitments(self):
        participant_ids = list(range(1, self.tp.n + 1))
        participants = [participant.Participant(id, participant_ids, self.cp, self.tp) for id in participant_ids]

        # via broadcast
        # participants[0] is missing participants[1]'s commitment
        for pj in participants[2:]:
            closed_commitment = pj.closed_commmitment()
            participants[0].receive_closed_commitment(closed_commitment)

        with self.assertRaises(ThresholdCryptoError):
            participants[0].open_commitment()

    def test_not_enough_closed_commitments(self):
        participant_ids = list(range(1, self.tp.n + 1))
        participants = [participant.Participant(id, participant_ids, self.cp, self.tp) for id in participant_ids]

        # via broadcast
        for pi in participants:
            for pj in participants:
                if pj != pi:
                    closed_commitment = pj.closed_commmitment()
                    pi.receive_closed_commitment(closed_commitment)

        # via broadcast
        # participants[0] is missing participants[1]'s commitment
        for pj in participants[2:]:
            open_commitment = pj.open_commitment()
            participants[0].receive_open_commitment(open_commitment)

        with self.assertRaises(ThresholdCryptoError):
            participants[0].compute_public_key()

    def test_not_enough_F_ij_values(self):
        participant_ids = list(range(1, self.tp.n + 1))
        participants = [participant.Participant(id, participant_ids, self.cp, self.tp) for id in participant_ids]

        # via broadcast
        for pi in participants:
            for pj in participants:
                if pj != pi:
                    closed_commitment = pj.closed_commmitment()
                    pi.receive_closed_commitment(closed_commitment)

        # via broadcast
        for pi in participants:
            for pj in participants:
                if pj != pi:
                    open_commitment = pj.open_commitment()
                    pi.receive_open_commitment(open_commitment)

        # via broadcast
        # participants[0] is missing participants[1]'s F_ij value
        for pj in participants[2:]:
            F_ij = pj.F_ij_value()
            participants[0].receive_F_ij_value(F_ij)

        with self.assertRaises(ThresholdCryptoError):
            participants[0].s_ij_value_for_participant(2)

    def test_not_enough_s_ij_values(self):
        participant_ids = list(range(1, self.tp.n + 1))
        participants = [participant.Participant(id, participant_ids, self.cp, self.tp) for id in participant_ids]

        # via broadcast
        for pi in participants:
            for pj in participants:
                if pj != pi:
                    closed_commitment = pj.closed_commmitment()
                    pi.receive_closed_commitment(closed_commitment)

        # via broadcast
        for pi in participants:
            for pj in participants:
                if pj != pi:
                    open_commitment = pj.open_commitment()
                    pi.receive_open_commitment(open_commitment)

        public_key = participants[0].compute_public_key()
        for pk in [p.compute_public_key() for p in participants[1:]]:
            self.assertEqual(public_key, pk)

        # via broadcast
        for pi in participants:
            for pj in participants:
                if pj != pi:
                    F_ij = pj.F_ij_value()
                    pi.receive_F_ij_value(F_ij)

        # SECRETLY from i to j
        # participants[0] is missing participants[1]'s s_ij value
        for pj in participants[2:]:
            s_ij = pj.s_ij_value_for_participant(participants[0].id)
            participants[0].receive_sij(s_ij)

        with self.assertRaises(ThresholdCryptoError):
            participants[0].compute_share()
