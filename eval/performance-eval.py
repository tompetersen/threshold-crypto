import csv
import datetime
import os, sys
import time

currentdir = os.path.dirname(os.path.realpath(__file__))
parentdir = os.path.dirname(currentdir)
sys.path.append(parentdir)

import threshold_crypto as tc

current_date_time = datetime.datetime.now().strftime("%Y%m%d-%H%M")
EVAL_FILE_NAME = "eval-{}.txt".format(current_date_time)

TIMING_ROUNDS = 10000
GLOBAL_CP = tc.CurveParameters()
GLOBAL_VAR_TP_PARAMS = [
        (2, 3),
        (3, 5),
        (2, 10),
        (5, 10),
        (8, 10),
        (3, 20),
        (15, 20),
        (5, 50),
        (40, 50),
    ]

# message_sizes_in_bytes = [32, 10 ** 3, 10 ** 4, 10 ** 5, 10 ** 6]
MESSAGE_BYTE_SIZES = [5000 * i for i in range(1, 200)]
#MESSAGE_BYTE_SIZES = [50000 * i for i in range(1, 20)]


def write_csv(row):
    with open(EVAL_FILE_NAME, "a") as f:
        writer = csv.writer(f, )
        writer.writerow(row)


def eval_performance(task, params, func, timing_rounds=TIMING_ROUNDS, **kwargs):
    start = time.perf_counter()
    for _ in range(timing_rounds):
        func(**kwargs)
    stop = time.perf_counter()
    time_str = "{:0.3f}".format(stop - start)
    print(task, params, timing_rounds, time_str)
    write_csv([task, params, timing_rounds, time_str])


# EVALUATE CENTRAL KEY GENERATION


def eval_ckg(timing_rounds):
    for t, n in GLOBAL_VAR_TP_PARAMS:
        tp = tc.ThresholdParameters(t, n)

        eval_performance("CKG",
                         "({}, {})".format(t, n),
                         tc.create_public_key_and_shares_centralized,
                         curve_params=GLOBAL_CP,
                         threshold_params=tp,
                         timing_rounds=timing_rounds
                         )


# EVALUATE DKG


def run_dkg_centralized(thresh_params, curve_params):
    participant_ids = list(range(1, thresh_params.n + 1))
    participants = [tc.Participant(id, participant_ids, curve_params, thresh_params) for id in participant_ids]

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

    pks = [p.compute_public_key() for p in participants[1:]]

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


def eval_dkg(timing_rounds):
    for t, n in GLOBAL_VAR_TP_PARAMS:
        tp = tc.ThresholdParameters(t, n)
        eval_performance("DKG",
                         "({}, {})".format(t, n),
                         run_dkg_centralized,
                         timing_rounds=timing_rounds,
                         thresh_params=tp,
                         curve_params=GLOBAL_CP
                         )


# EVALUATE ENCRYPTION
# independent of tp, depends on message size (no huge impact)


def eval_enc(timing_rounds):
    tp = tc.ThresholdParameters(3, 5)
    pub_key, shares = tc.create_public_key_and_shares_centralized(GLOBAL_CP, tp)

    for msg_size in MESSAGE_BYTE_SIZES:
        msg = "a" * msg_size  # since encryption uses utf-8 encoding, this leads to messages of size msg_size
        eval_performance("Encrypt",
                         "{}".format(msg_size),
                         tc.encrypt_message,
                         message=msg,
                         public_key=pub_key,
                         timing_rounds=timing_rounds
                         )


# EVALUATE DECRYPTION depending on msg size
# independent of tp, depends on message size (no huge impact)


def eval_dec_msg_size(timing_rounds, t=2, n=3):
    tp = tc.ThresholdParameters(t, n)
    pub_key, shares = tc.create_public_key_and_shares_centralized(GLOBAL_CP, tp)

    for msg_size in MESSAGE_BYTE_SIZES:
        msg = "a" * msg_size
        enc_msg = tc.encrypt_message(msg, pub_key)
        pds = [tc.compute_partial_decryption(enc_msg, share) for share in shares[:t]]

        eval_performance("Decrypt" + str(t) + str(n),
                         "{}".format(msg_size),
                         tc.decrypt_message,
                         partial_decryptions=pds,
                         encrypted_message=enc_msg,
                         threshold_params=tp,
                         timing_rounds=timing_rounds
                         )


# EVALUATE PARTIAL DECRYPTION COMPUTATION


def eval_pd(timing_rounds):
    tp = tc.ThresholdParameters(3, 5)
    pub_key, shares = tc.create_public_key_and_shares_centralized(GLOBAL_CP, tp)
    em = tc.encrypt_message("a", pub_key)
    eval_performance("PartialDecryption",
                     "",
                     tc.compute_partial_decryption,
                     encrypted_message=em,
                     key_share=shares[0],
                     timing_rounds=timing_rounds
                     )


# EVALUATE DECRYPTION (combine partial decryptions)
# we have tried it with different message sizes, but these did not matter at all.
# The threshold parameters are the relevant part.

# message_sizes_in_bytes = [16384, 81920, 147456]  # subset of message_sizes_in_bytes from above
# for (t, n), msg_size in itertools.product(diff_tp_params, message_sizes_in_bytes):


def eval_dec(timing_rounds):
    msg_size = 1024
    msg = "a" * msg_size

    for (t, n) in GLOBAL_VAR_TP_PARAMS:
        tp = tc.ThresholdParameters(t, n)
        pub_key, shares = tc.create_public_key_and_shares_centralized(GLOBAL_CP, tp)
        enc_msg = tc.encrypt_message(msg, pub_key)
        pds = [tc.compute_partial_decryption(enc_msg, share) for share in shares[:t]]

        eval_performance("DecryptCombine",
                         "({}, {})".format(t, n),
                         tc.decrypt_message,
                         partial_decryptions=pds,
                         encrypted_message=enc_msg,
                         threshold_params=tp,
                         timing_rounds=timing_rounds
                         )


# EVALUATE PARTIAL PROXY KEY COMPUTATION


def eval_prek():
    tp = tc.ThresholdParameters(5, 10)
    _, old_shares = tc.create_public_key_and_shares_centralized(GLOBAL_CP, tp)
    _, new_shares = tc.create_public_key_and_shares_centralized(GLOBAL_CP, tp)
    t_old_shares_x = [share.x for share in old_shares[:tp.t]]
    t_new_shares_x = [share.x for share in new_shares[:tp.t]]
    old_lc = tc.lagrange_coefficient_for_key_share_indices(t_old_shares_x, t_old_shares_x[0], GLOBAL_CP)
    new_lc = tc.lagrange_coefficient_for_key_share_indices(t_new_shares_x, t_new_shares_x[0], GLOBAL_CP)

    eval_performance("PartialReEncryptionKey",
                     "",
                     tc.compute_partial_re_encryption_key,
                     old_share=old_shares[0],
                     old_lc=old_lc,
                     new_share=new_shares[0],
                     new_lc=new_lc
                     )


# EVALUATE PARTIAL PROXY KEY COMBINATION
# minor impact of AS in comparison to others


def eval_rek():
    # for t, n in GLOBAL_VAR_TP_PARAMS:
    t, n = 3, 5
    tp = tc.ThresholdParameters(t, n)
    _, old_shares = tc.create_public_key_and_shares_centralized(GLOBAL_CP, tp)
    _, new_shares = tc.create_public_key_and_shares_centralized(GLOBAL_CP, tp)
    t_old_shares = old_shares[:t]
    t_new_shares = new_shares[:t]
    t_old_shares_x = [share.x for share in t_old_shares]
    t_new_shares_x = [share.x for share in t_new_shares]
    old_lc = [tc.lagrange_coefficient_for_key_share_indices(t_old_shares_x, s, GLOBAL_CP) for s in t_old_shares_x]
    new_lc = [tc.lagrange_coefficient_for_key_share_indices(t_new_shares_x, s, GLOBAL_CP) for s in t_new_shares_x]
    prek = []
    for os, olc, ns, nlc in zip(t_old_shares, old_lc, t_new_shares, new_lc):
        prek.append(tc.compute_partial_re_encryption_key(os, olc, ns, nlc))

    eval_performance("ReEncryptionKeyCombination",
                     "({}, {})".format(t, n),
                     tc.combine_partial_re_encryption_keys,
                     partial_keys=prek,
                     old_threshold_params=tp,
                     new_threshold_params=tp
                     )


# EVALUATE RE_ENCRYPTION


def eval_reenc(timing_rounds):
    tp = tc.ThresholdParameters(5, 10)

    old_pub_key, old_shares = tc.create_public_key_and_shares_centralized(GLOBAL_CP, tp)
    new_pub_key, new_shares = tc.create_public_key_and_shares_centralized(GLOBAL_CP, tp)
    t_old_shares = old_shares[:tp.t]
    t_new_shares = new_shares[:tp.t]
    t_old_shares_x = [share.x for share in t_old_shares]
    t_new_shares_x = [share.x for share in t_new_shares]
    old_lc = [tc.lagrange_coefficient_for_key_share_indices(t_old_shares_x, s, GLOBAL_CP) for s in t_old_shares_x]
    new_lc = [tc.lagrange_coefficient_for_key_share_indices(t_new_shares_x, s, GLOBAL_CP) for s in t_new_shares_x]
    prek = []
    for os, olc, ns, nlc in zip(t_old_shares, old_lc, t_new_shares, new_lc):
        prek.append(tc.compute_partial_re_encryption_key(os, olc, ns, nlc))
    re_encryption_key = tc.combine_partial_re_encryption_keys(prek, old_pub_key, new_pub_key, tp, tp)

    em = tc.encrypt_message("a", old_pub_key)

    eval_performance("ReEncrypt",
                     "",
                     tc.re_encrypt_message,
                     em=em,
                     re_key=re_encryption_key,
                     timing_rounds=timing_rounds
                     )


# MAIN RUN


def main():
    write_csv(['task', 'parameters', 'rounds', 'time'])

    eval_ckg(timing_rounds=1)
    eval_dkg(timing_rounds=1)
    eval_enc(1000)
    eval_dec_msg_size(1000)
    eval_dec_msg_size(1000, t=3, n=5)
    eval_dec_msg_size(1000, t=2, n=10)
    eval_dec(timing_rounds=1000)
    eval_pd(timing_rounds=1000)
    eval_prek()
    eval_rek()
    eval_reenc(timing_rounds=1000)

    print("Done! Written to {}".format(EVAL_FILE_NAME))


if __name__ == '__main__':
    main()
