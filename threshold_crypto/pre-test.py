import number



p = 7452962895294639129334402125897500494888232626693057568141676237916133687836239813279595639173262006234190877985012715032067188198462763852940914332974923
q = 3726481447647319564667201062948750247444116313346528784070838118958066843918119906639797819586631003117095438992506357516033594099231381926470457166487461
g = 1291791552707048245090176929539921926555612768576578304996066408519254635531597933040589792119803333400907701386210407460215915386675734438575583315866662



m = 234567

# first keypair
sk1 = number.getRandomRange(2, p - 1)
pk1 = pow(g, sk1, p)
print("Keypair1: ", sk1, pk1)

# encrypt
k = number.getRandomRange(1, q - 1)
c1 = (pow(g, k, p), (m * pow(pk1, k, p)) % p)

print("c1_2: ", c1)

# # decrypt
# g_sk_k = pow(c1[0], sk1, p)
# g_minus_sk_k = number.prime_mod_inv(g_sk_k, p)
# restored_m = c1[1] * g_minus_sk_k % p
# assert m == restored_m, "Message and decrypted message differ"

# second keypair
sk2 = number.getRandomRange(2, p - 1)
pk2 = pow(g, sk2, p)
print("Keypair2: ", sk2, pk2)

# # encrypt second
# c2_1_tmp = c1
# c2_2_tmp = (m * pow(pk2, k, p)) % p

# reencrypt (my scheme)
pi_12 = (sk2 - sk1) % q
c2 = (c1[0], (c1[1] * pow(c1[0], pi_12, p)) % p)
print("pi12: ", pi_12)
print("reencrypted: ", c2)

# assert c2_2_tmp == c2[1], "encryption and reencryption differ"

# decrypt second

g_sk2_k = pow(c2[0], sk2, p)
g_minus_sk2_k = number.prime_mod_inv(g_sk2_k, p)
restored_m = (c2[1] * g_minus_sk2_k) % p
assert m == restored_m, "Message and decrypted message differ for reencrypt"

print("Done")


