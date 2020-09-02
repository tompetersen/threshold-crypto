# Threshold cryptography library


A stateless library which offers functionality for ElGamal-based threshold decryption with centralized key generation.

Threshold decryption means a message can be encrypted using a simple public key, but for decryption at least t out of n
share owners must collaborate to decrypt the message.

A hybrid approach (using pynacl for symmetric encryption) is used for message encryption and decryption.
Therefor there are no limitations regarding message lengths or format. Additionally the integrity of a message is
secured by using the AE-scheme, meaning changes to some parts of the ciphertext, to partial decryptions or even
dishonest share owners can be detected.

**Warning**: This library has never been (independently) audited and should not be used for productive applications.

## Usage

Import the library:

    >>> import threshold_crypto as tc

### Parameter Generation

Generate required parameters:

    >>> curve_params = tc.CurveParameters()
    >>> thresh_params = tc.ThresholdParameters(t=3, n=5)

The `CurveParameters` describe the elliptic curve the operations are performed on. 
The `ThresholdParameters` determine the number of created shares `n` and the number of required participants for the decryption operation `t`.

### Centralized Key Generation

The public key and shares of the private key can be computed in a centralized manner by a trusted third party:

    >>> pub_key, key_shares = tc.create_public_key_and_shares_centralized(curve_params, thresh_params)

### Distributed Key Generation

TODO

### Encryption

A message is encrypted using the public key:

    >>> message = 'Some secret message to be encrypted!'
    >>> encrypted_message = tc.encrypt_message(message, pub_key)

### Computing Partial Decryptions

`t` share owners compute partial decryptions of a ciphertext using their shares:

    >>> partial_decryptions = []
    >>> for participant in [0, 2, 4]:
    ...     participant_share = key_shares[participant]
    ...     partial_decryption = tc.compute_partial_decryption(encrypted_message, participant_share)
    ...     partial_decryptions.append(partial_decryption)

### Combining Partial Decryptions

Combine these partial decryptions to recover the message:

    >>> decrypted_message = tc.decrypt_message(partial_decryptions, encrypted_message, thresh_params)
    >>> print(decrypted_message)
    Some secret message to be encrypted!

### Updating Ciphertexts

When the participants of the scheme change (adding participants, removing participants, ...) existing ciphertexts can be re-encrypted to be decryptable with the new shares.

First, create the new shares (for simplicity the centralized approach is shown here, in practice you want to use distributed key generation):

    >>> new_pub_key, new_key_shares = tc.create_public_key_and_shares_centralized(curve_params, thresh_params)

A third party computes non-secret values required for the generation of the re-encryption key for `max(t_old, t_new)` participants involved in the re-encryption key generation:

    >>> t_max = thresh_params.t
    >>> old_indices = [key_share.x for key_share in key_shares][:t_max]
	>>> new_indices = [key_share.x for key_share in new_key_shares][:t_max]

	>>> coefficients = []
	>>> for p in range(t_max):
	...     old_lc = tc.compute_lagrange_coefficient_for_key_shares_indices(old_indices, curve_params, p)
	...     new_lc = tc.compute_lagrange_coefficient_for_key_shares_indices(new_indices, curve_params, p)
	...     coefficients.append((old_lc, new_lc))
	
 A number of `max(t_old, t_new)` participants now compute their partial re-encryption keys using these non-secret values and his shares:

	>>> partial_re_enc_keys = []
    >>> for p in range(t_max):
    ...     old_share = key_shares[p]
    ...     new_share = new_key_shares[p]
    ...     old_lc, new_lc = coefficients[p]
    ...     partial_re_enc_key = tc.compute_partial_re_encryption_key(old_share, old_lc, new_share, new_lc)
    ...     partial_re_enc_keys.append(partial_re_enc_key)
 
The third party computes the re-encryption key by combining the partial re-encryption keys:
 
	>>> re_enc_key = tc.combine_partial_re_encryption_keys(partial_re_enc_keys, thresh_params, thresh_params)

The encrypted message is re-encrypted to be decryptable by the new shares:

	>>> new_encrypted_message = tc.re_encrypt_message(encrypted_message, re_enc_key)

Decryption can now be performed using the new shares:

    >>> reconstruct_shares = [new_key_shares[i] for i in [0, 2, 4]]
    >>> partial_decryptions = [tc.compute_partial_decryption(new_encrypted_message, share) for share in reconstruct_shares]
    >>> decrypted_message = tc.decrypt_message(partial_decryptions, new_encrypted_message, thresh_params)
    >>> print(decrypted_message)
    Some secret message to be encrypted!

## Stuff?!