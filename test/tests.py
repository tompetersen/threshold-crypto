import unittest

from threshold_crypto.data import (ThresholdParameters,
                                   KeyParameters,
                                   ThresholdCryptoError,
                                   PublicKey,
                                   KeyShare,
                                   EncryptedMessage,
                                   PartialDecryption,
                                   )
from threshold_crypto import number
from threshold_crypto import central, Participant
from threshold_crypto import participant


class TCTestCase(unittest.TestCase):

    def setUp(self):
        self.tp = ThresholdParameters(3, 5)
        self.kp = central.static_512_key_parameters()
        self.pk, self.shares = central.create_public_key_and_shares_centralized(self.kp, self.tp)
        self.message = 'Some secret message'
        self.em = central.encrypt_message(self.message, self.pk)
        self.reconstruct_shares = [self.shares[i] for i in [0, 2, 4]]  # choose 3 of 5 key shares
        self.partial_decryptions = [participant.compute_partial_decryption(self.em, share) for share in self.reconstruct_shares]

    def tearDown(self):
        pass

    def test_valid_threshold_parameters(self):
        t = ThresholdParameters(3, 5)

    def test_invalid_threshold_parameters(self):
        with self.assertRaises(ThresholdCryptoError):
            t = ThresholdParameters(5, 3)

    def test_threshold_parameter_json(self):
        t = ThresholdParameters(3, 5)
        t_j = ThresholdParameters.from_json(t.to_json())

        self.assertEqual(t, t_j)

    def test_valid_key_parameters(self):
        k = KeyParameters(7, 3, 2)  # 2 generates 3-order subgroup {1,2,4}

    def test_invalid_key_parameters_whole_group(self):
        with self.assertRaises(ThresholdCryptoError):
            k = KeyParameters(7, 3, 3)  # 3 generates 6-order group Z_7*

    def test_invalid_key_parameters_no_safe_prime(self):
        with self.assertRaises(ThresholdCryptoError):
            k = KeyParameters(7, 4, 3)

    def test_key_parameter_json(self):
        k_j = KeyParameters.from_json(self.kp.to_json())

        self.assertEqual(self.kp, k_j)

    def test_static_512_key_parameters(self):
        kp = central.static_512_key_parameters()

        self.assertEqual(kp.p, 2*kp.q + 1)  # safe prime
        self.assertEqual(pow(kp.g, kp.q, kp.p), 1)  # g generates q order subgroup
        self.assertNotEqual(pow(kp.g, 2, kp.p), 1)

    def test_static_1024_key_parameters(self):
        kp = central.static_1024_key_parameters()

        self.assertEqual(kp.p, 2*kp.q + 1)  # safe prime
        self.assertEqual(pow(kp.g, kp.q, kp.p), 1)  # g generates q order subgroup
        self.assertNotEqual(pow(kp.g, 2, kp.p), 1)

    def test_static_2048key_parameters(self):
        kp = central.static_2048_key_parameters()

        self.assertEqual(kp.p, 2 * kp.q + 1)  # safe prime
        self.assertEqual(pow(kp.g, kp.q, kp.p), 1)  # g generates q order subgroup
        self.assertNotEqual(pow(kp.g, 2, kp.p), 1)

    def test_central_key_generation(self):
        pk, shares = central.create_public_key_and_shares_centralized(self.kp, self.tp)

        self.assertEqual(pk.key_parameters, self.kp)
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

        self.assertTrue(em.c >= 0)
        self.assertTrue(em.v >= 0)

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
        r = number.getRandomRange(2, self.kp.q)
        testkey_element = pow(self.kp.g, r, self.kp.p)
        g_k, c = central._encrypt_key_element(testkey_element, self.pk)
        em = EncryptedMessage(g_k, c, '')
        reconstruct_shares = [self.shares[i] for i in [0, 2, 4]]  # choose 3 of 5 key shares
        partial_decryptions = [participant.compute_partial_decryption(em, share) for share in reconstruct_shares]
        rec_testkey_element = central._combine_shares(partial_decryptions, em, self.tp, self.kp)

        self.assertEqual(testkey_element, rec_testkey_element)

    def test_key_encryption_decryption_without_enough_shares(self):
        r = number.getRandomRange(2, self.kp.q)
        testkey_element = pow(self.kp.g, r, self.kp.p)
        g_k, c = central._encrypt_key_element(testkey_element, self.pk)
        em = EncryptedMessage(g_k, c, '')
        reconstruct_shares = [self.shares[i] for i in [0, 4]]  # choose 2 of 5 key shares
        partial_decryptions = [participant.compute_partial_decryption(em, share) for share in reconstruct_shares]
        rec_testkey_element = central._combine_shares(partial_decryptions, em, self.tp, self.kp)

        self.assertNotEqual(testkey_element, rec_testkey_element)

    def test_complete_process_with_enough_shares(self):
        key_params = central.static_512_key_parameters()
        thresh_params = ThresholdParameters(3, 5)

        pub_key, key_shares = central.create_public_key_and_shares_centralized(key_params, thresh_params)

        message = 'Some secret message to be encrypted!'
        encrypted_message = central.encrypt_message(message, pub_key)

        reconstruct_shares = [key_shares[i] for i in [0, 2, 4]]  # choose 3 of 5 key shares
        partial_decryptions = [participant.compute_partial_decryption(encrypted_message, share) for share in reconstruct_shares]
        decrypted_message = central.decrypt_message(partial_decryptions, encrypted_message, thresh_params, key_params)

        self.assertEqual(message, decrypted_message)

    def test_complete_process_without_enough_shares(self):
        key_params = central.static_512_key_parameters()
        thresh_params = ThresholdParameters(3, 5)

        pub_key, key_shares = central.create_public_key_and_shares_centralized(key_params, thresh_params)

        message = 'Some secret message to be encrypted!'
        encrypted_message = central.encrypt_message(message, pub_key)

        reconstruct_shares = [key_shares[i] for i in [3, 4]]  # choose 2 of 5 key shares
        partial_decryptions = [participant.compute_partial_decryption(encrypted_message, share) for share in reconstruct_shares]

        with self.assertRaises(ThresholdCryptoError):
            central.decrypt_message(partial_decryptions, encrypted_message, thresh_params, key_params)


class PreTestCase(unittest.TestCase):
    """
    Test cases for the proxy reencryption scheme.
    """

    def setUp(self):
        self.tp = ThresholdParameters(3, 5)
        self.kp = central.static_512_key_parameters()
        self.pk, self.shares = central.create_public_key_and_shares_centralized(self.kp, self.tp)
        self.message = 'Some secret message'
        self.em = central.encrypt_message(self.message, self.pk)
        self.reconstruct_shares = [self.shares[i] for i in [0, 2, 4]]  # choose 3 of 5 key shares
        self.partial_decryptions = [participant.compute_partial_decryption(self.em, share) for share in
                                    self.reconstruct_shares]

    def tearDown(self):
        pass

    def test_re_encryption_process_for_same_access_structures(self):
        """ """
        new_pk, new_shares = central.create_public_key_and_shares_centralized(self.kp, self.tp)

        assert new_pk != self.pk, "Public keys for new and old access structure are the same"

        t_old_shares = self.shares[:self.tp.t]
        t_new_shares = new_shares[:self.tp.t]
        partial_re_encrypt_keys = []

        for i, (s_old, s_new) in enumerate(zip(t_old_shares, t_new_shares)):
            old_lambda = participant._compute_lagrange_coefficient_for_key_shares(t_old_shares, i)
            new_lambda = participant._compute_lagrange_coefficient_for_key_shares(t_new_shares, i)
            partial_key = participant.compute_partial_re_encryption_key(s_old, old_lambda, s_new, new_lambda)
            partial_re_encrypt_keys.append(partial_key)

        re_encrypt_key = central.combine_partial_re_encryption_keys(partial_re_encrypt_keys, self.tp, self.tp)
        re_em = central.re_encrypt_message(self.em, re_encrypt_key)

        self.assertNotEqual(self.em, re_em)

        new_reconstruct_shares = [new_shares[i] for i in [0, 2, 4]]
        new_partial_decryptions = [participant.compute_partial_decryption(re_em, share) for share in new_reconstruct_shares]

        decrypted_message = central.decrypt_message(new_partial_decryptions, re_em, self.tp, self.kp)

        self.assertEqual(self.message, decrypted_message)


class DkgTestCase(unittest.TestCase):
    """
    Test cases for the distributed key generation.
    """

    def setUp(self):
        self.tp = ThresholdParameters(3, 5)
        self.kp = central.static_512_key_parameters()
        self.message = 'Some secret message'

    def tearDown(self):
        pass

    def test_distributed_key_generation(self):
        participants = [Participant(id, self.kp, self.tp) for id in range(1, self.tp.n + 1)]

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
        public_key = central.create_public_key(p_his, self.kp, self.tp)

        # test encryption/decryption

        em = central.encrypt_message(self.message, public_key)

        shares = [p.key_share for p in participants]
        pdms = [participant.compute_partial_decryption(em, ks) for ks in shares[:self.tp.t]]
        dm = central.decrypt_message(pdms, em, self.tp, self.kp)

        self.assertEqual(dm, self.message)
