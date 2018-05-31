Threshold cryptography library
------------------------------

A stateless library which offers functionality for ElGamal-based threshold decryption with centralized key generation.

Threshold decryption means a message can be encrypted using a simple public key, but for decryption at least t out of n
share owners must collaborate to decrypt the message.

A hybrid approach (using pynacl for symmetric encryption) is used for message encryption and decryption.
Therefor there are no limitations regarding message lengths or format. Additionally the integrity of a message is
secured by using the AE-scheme, meaning changes to some parts of the ciphertext, to partial decryptions or even
dishonest share owners can be detected.

Usage
-----

.. code:: python

    from threshold_crypto import (ThresholdCrypto, ThresholdParameters)

    # Generate parameters, public key and shares
    key_params = ThresholdCrypto.static_2048_key_parameters()
    thresh_params = ThresholdParameters(3, 5)
    pub_key, key_shares = ThresholdCrypto.create_public_key_and_shares_centralized(key_params, thresh_params)

    # encrypt message using the public key
    message = 'Some secret message to be encrypted!'
    encrypted_message = ThresholdCrypto.encrypt_message(message, pub_key)

    # build partial decryptions of three share owners using their shares
    reconstruct_shares = [key_shares[i] for i in [0, 2, 4]]
    partial_decryptions = [ThresholdCrypto.compute_partial_decryption(encrypted_message, share) for share in reconstruct_shares]

    # combine these partial decryptions to recover the message
    decrypted_message = ThresholdCrypto.decrypt_message(partial_decryptions, encrypted_message, thresh_params, key_params)

