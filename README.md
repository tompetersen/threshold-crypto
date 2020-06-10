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

### parameter generation

```python
import threshold_crypto as tc

key_params = tc.static_2048_key_parameters()
thresh_params = tc.ThresholdParameters(3, 5)
```

### centralized key generation

```python
pub_key, key_shares = tc.create_public_key_and_shares_centralized(key_params, thresh_params)
```

### distributed key generation

```python
# TODO
```

### encryption and decryption

```python
# encrypt message using the public key
message = 'Some secret message to be encrypted!'
encrypted_message = tc.encrypt_message(message, pub_key)

# build partial decryptions of three share owners using their shares
reconstruct_shares = [key_shares[i] for i in [0, 2, 4]]
partial_decryptions = [tc.compute_partial_decryption(encrypted_message, share) for share in reconstruct_shares]

# combine these partial decryptions to recover the message
decrypted_message = tc.decrypt_message(partial_decryptions, encrypted_message, thresh_params, key_params)
```

### updating access structures via PRE

```python
# TODO
```