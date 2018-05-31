import unittest

from threshold_crypto import (ThresholdCrypto,
                              ThresholdParameters,
                              KeyParameters,
                              PolynomMod,
                              ThresholdCryptoError,
                              PublicKey,
                              KeyShare,
                              EncryptedMessage,
                              PartialDecryption,
                              number)


class TCTestCase(unittest.TestCase):

    def setUp(self):
        self.tp = ThresholdParameters(3, 5)
        self.kp = ThresholdCrypto.static_512_key_parameters()
        self.pk, self.shares = ThresholdCrypto.create_public_key_and_shares_centralized(self.kp, self.tp)
        self.em = ThresholdCrypto.encrypt_message('Some secret message', self.pk)
        self.reconstruct_shares = [self.shares[i] for i in [0, 2, 4]]  # choose 3 of 5 key shares
        self.partial_decryptions = [ThresholdCrypto.compute_partial_decryption(self.em, share) for share in self.reconstruct_shares]

    def tearDown(self):
        pass

    def test_valid_threshold_parameters(self):
        t = ThresholdParameters(3,5)

    def test_invalid_threshold_parameters(self):
        with self.assertRaises(ThresholdCryptoError):
            t = ThresholdParameters(5,3)

    def test_threshold_parameter_json(self):
        t = ThresholdParameters(3, 5)
        t_j = ThresholdParameters.from_json(t.to_json())

        self.assertEqual(t, t_j)

    def test_valid_key_parameters(self):
        k = KeyParameters(7, 3, 2) # 2 generates 3-order subgroup {1,2,4}

    def test_invalid_key_parameters_whole_group(self):
        with self.assertRaises(ThresholdCryptoError):
            k = KeyParameters(7, 3, 3) # 3 generates 6-order group Z_7*

    def test_invalid_key_parameters_no_safe_prime(self):
        with self.assertRaises(ThresholdCryptoError):
            k = KeyParameters(7, 4, 3)

    def test_key_parameter_json(self):
        k_j = KeyParameters.from_json(self.kp.to_json())

        self.assertEqual(self.kp, k_j)

    def test_static_512_key_parameters(self):
        kp = ThresholdCrypto.static_512_key_parameters()

        self.assertEqual(kp.p, 2*kp.q + 1) # safe prime
        self.assertEqual(pow(kp.g, kp.q, kp.p), 1) # g generates q order subgroup
        self.assertNotEqual(pow(kp.g, 2, kp.p), 1)

    def test_static_1024_key_parameters(self):
        kp = ThresholdCrypto.static_1024_key_parameters()

        self.assertEqual(kp.p, 2*kp.q + 1) # safe prime
        self.assertEqual(pow(kp.g, kp.q, kp.p), 1) # g generates q order subgroup
        self.assertNotEqual(pow(kp.g, 2, kp.p), 1)

    def test_static_2048key_parameters(self):
        kp = ThresholdCrypto.static_2048_key_parameters()

        self.assertEqual(kp.p, 2 * kp.q + 1)  # safe prime
        self.assertEqual(pow(kp.g, kp.q, kp.p), 1)  # g generates q order subgroup
        self.assertNotEqual(pow(kp.g, 2, kp.p), 1)

    def test_central_key_generation(self):
        pk, shares = ThresholdCrypto.create_public_key_and_shares_centralized(self.kp, self.tp)

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
        em = ThresholdCrypto.encrypt_message('Some secret message', self.pk)

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
        p = PolynomMod.create_random_polynom(17, 5, 41)

        self.assertTrue(p.degree == 5)
        self.assertTrue(p.evaluate(0) == 17)

    def test_key_encryption_decryption_with_enough_shares(self):
        r = number.getRandomRange(2, self.kp.q)
        testkey_element = pow(self.kp.g, r, self.kp.p)
        g_k, c = ThresholdCrypto._encrypt_key_element(testkey_element, self.pk)
        em = EncryptedMessage(g_k, c, '')
        reconstruct_shares = [self.shares[i] for i in [0, 2, 4]]  # choose 3 of 5 key shares
        partial_decryptions = [ThresholdCrypto.compute_partial_decryption(em, share) for share in reconstruct_shares]
        rec_testkey_element = ThresholdCrypto._combine_shares(partial_decryptions, em, self.tp, self.kp)

        self.assertEqual(testkey_element, rec_testkey_element)

    def test_key_encryption_decryption_without_enough_shares(self):
        r = number.getRandomRange(2, self.kp.q)
        testkey_element = pow(self.kp.g, r, self.kp.p)
        g_k, c = ThresholdCrypto._encrypt_key_element(testkey_element, self.pk)
        em = EncryptedMessage(g_k, c, '')
        reconstruct_shares = [self.shares[i] for i in [0, 4]]  # choose 2 of 5 key shares
        partial_decryptions = [ThresholdCrypto.compute_partial_decryption(em, share) for share in reconstruct_shares]
        rec_testkey_element = ThresholdCrypto._combine_shares(partial_decryptions, em, self.tp, self.kp)

        self.assertNotEqual(testkey_element, rec_testkey_element)

    def test_complete_process_with_enough_shares(self):
        key_params = ThresholdCrypto.static_512_key_parameters()
        thresh_params = ThresholdParameters(3, 5)

        pub_key, key_shares = ThresholdCrypto.create_public_key_and_shares_centralized(key_params, thresh_params)

        message = 'Some secret message to be encrypted!'
        encrypted_message = ThresholdCrypto.encrypt_message(message, pub_key)

        reconstruct_shares = [key_shares[i] for i in [0, 2, 4]] # choose 3 of 5 key shares
        partial_decryptions = [ThresholdCrypto.compute_partial_decryption(encrypted_message, share) for share in reconstruct_shares]
        decrypted_message = ThresholdCrypto.decrypt_message(partial_decryptions, encrypted_message, thresh_params, key_params)

        self.assertEqual(message, decrypted_message)

    def test_complete_process_without_enough_shares(self):
        key_params = ThresholdCrypto.static_512_key_parameters()
        thresh_params = ThresholdParameters(3, 5)

        pub_key, key_shares = ThresholdCrypto.create_public_key_and_shares_centralized(key_params, thresh_params)

        message = 'Some secret message to be encrypted!'
        encrypted_message = ThresholdCrypto.encrypt_message(message, pub_key)

        reconstruct_shares = [key_shares[i] for i in [3, 4]] # choose 2 of 5 key shares
        partial_decryptions = [ThresholdCrypto.compute_partial_decryption(encrypted_message, share) for share in reconstruct_shares]

        with self.assertRaises(ThresholdCryptoError):
            decrypted_message = ThresholdCrypto.decrypt_message(partial_decryptions, encrypted_message, thresh_params, key_params)
