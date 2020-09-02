import unittest

from threshold_crypto.data import (ThresholdParameters,
                                   CurveParameters,
                                   ThresholdCryptoError,
                                   KeyShare,
                                   EncryptedMessage,
                                   PartialDecryption,
                                   PartialReEncryptionKey,
                                   ReEncryptionKey,
                                   PublicKey,
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
        r = number.getRandomRange(2, self.cp.order)
        testkey_element = r * self.cp.P
        kP, c = central._encrypt_key_point(testkey_element, self.pk.Q, self.cp)
        em = EncryptedMessage(kP, c, b'')
        reconstruct_shares = [self.shares[i] for i in [0, 2, 4]]  # choose 3 of 5 key shares
        partial_decryptions = [participant.compute_partial_decryption(em, share) for share in reconstruct_shares]
        rec_testkey_element = central._combine_shares(partial_decryptions, em, self.tp, self.cp)

        self.assertEqual(testkey_element, rec_testkey_element)

    def test_key_encryption_decryption_without_enough_shares(self):
        r = number.getRandomRange(2, self.cp.order)
        testkey_element = r * self.cp.P
        kP, c = central._encrypt_key_point(testkey_element, self.pk.Q, self.cp)
        em = EncryptedMessage(kP, c, b'')
        reconstruct_shares = [self.shares[i] for i in [0, 4]]  # choose 2 of 5 key shares
        partial_decryptions = [participant.compute_partial_decryption(em, share) for share in reconstruct_shares]
        rec_testkey_element = central._combine_shares(partial_decryptions, em, self.tp, self.cp)

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
        """ """
        new_pk, new_shares = central.create_public_key_and_shares_centralized(self.cp, self.tp)

        assert new_pk != self.pk, "Public keys for new and old access structure are the same"

        t_old_shares = self.shares[:self.tp.t]
        t_old_shares_x = [share.x for share in t_old_shares]
        t_new_shares = new_shares[:self.tp.t]
        t_new_shares_x = [share.x for share in t_new_shares]
        partial_re_encrypt_keys = []

        for i, (s_old, s_new) in enumerate(zip(t_old_shares, t_new_shares)):
            old_lambda = central.lagrange_coefficient_for_key_share_indices(t_old_shares_x, t_old_shares_x[i], self.cp)
            new_lambda = central.lagrange_coefficient_for_key_share_indices(t_new_shares_x, t_new_shares_x[i], self.cp)
            partial_key = participant.compute_partial_re_encryption_key(s_old, old_lambda, s_new, new_lambda)
            partial_re_encrypt_keys.append(partial_key)

        re_encrypt_key = central.combine_partial_re_encryption_keys(partial_re_encrypt_keys, self.tp, self.tp)
        re_em = central.re_encrypt_message(self.em, re_encrypt_key)

        self.assertNotEqual(self.em, re_em)

        new_reconstruct_shares = [new_shares[i] for i in [0, 2, 4]]
        new_partial_decryptions = [participant.compute_partial_decryption(re_em, share) for share in new_reconstruct_shares]

        decrypted_message = central.decrypt_message(new_partial_decryptions, re_em, self.tp)

        self.assertEqual(self.message, decrypted_message)


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

    def test_distributed_key_generation(self):
        participants = [participant.Participant(id, self.cp, self.tp) for id in range(1, self.tp.n + 1)]

        # steps for Pedersen DKG protocol
        for pi in participants:
            for pj in participants:
                pi.receive_F(pj.node_id, pj._local_F_ij)

        node_ids = [p.node_id for p in participants]
        for p in participants:
            p.calculate_sij(node_ids)

        for pi in participants:
            for pj in participants:
                pi.receive_sij(pj.node_id, pj._local_sij[pi.node_id])

        for p in participants:
            p.compute_share()

        p_his = [p.h_i for p in participants]
        public_key = central.create_public_key(p_his, self.cp, self.tp)

        # test encryption/decryption

        em = central.encrypt_message(self.message, public_key)

        shares = [p.key_share for p in participants]
        pdms = [participant.compute_partial_decryption(em, ks) for ks in shares[:self.tp.t]]
        dm = central.decrypt_message(pdms, em, self.tp)

        self.assertEqual(dm, self.message)
