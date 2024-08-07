from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import binascii
import random

key_pem = "-----BEGIN PUBLIC KEY-----\n\
MIIBtjCCASsGByqGSM44BAEwggEeAoGBAMru3+fqTHjUXRjgmXBzxtEMXceRdXVK\n\
SxQYWEb2zHFkc8MVBxE41Cgv9sVsNTFI9VsIlVrSyXHeUJ6LKznZOjC5qWEawR9E\n\
bBpCZlc0uDjc8NbQ9MFQkgw0TmERn/Xg1SjY8z6aaVR8BwT6/Bt/63AxdOmH9UPK\n\
ullMaqDruzplAhUAmzGsd2tN44X8WEdvdK+RKIj/SasCgYAmyasijKGmEDEJZrR0\n\
TPDxPFas8MlyPNSYj4zokNm5JG/2DsDoAyVlGQkRgEjET3a15OQazLRX2FC9hRZI\n\
XH87TLH2XyTzm9SzBBmKcfF8r/kyoWfNkDq6kU27RWZO6oVPZqrNi5T+ncS5amnM\n\
AUiij85K0LaIYPxczZL1s2qGhAOBhAACgYAlD9gc7GKnLQ4N4yfZrAdoAxkXpNSC\n\
xN9d8FUsuADHjgMMybDKOGyELdLn5dDOFRZd4qnykEndEuM5hZqBZPWHBj3AJ5Xd\n\
XXnWzMay1oatMHKPs1mi1wVKgtsk2GZu/OEJm2y/lEZfNUTA6jc/Q9Jqiemh2dOm\n\
AOf/PuTH08Td3Q==\n\
-----END PUBLIC KEY-----\n\
"
param_key = DSA.import_key(key_pem)
params = [param_key.p, param_key.q, param_key.g]

pub_keys = []
pvt_keys = []

signatures = []

message = b"CSCI301 Contemporary Topics in Security 2023"


def main():
    # Require user input until condition N >= M is matched
    while True:
        print("The number of public keys (N) should be equal to or greater than the number of signatures (M).")
        m = int(input("Enter the number of signatures (M): "))
        n = int(input("Enter the number of public keys (N): "))

        if n >= m:
            break

    # Write public key(s) to scriptPubkey.txt
    file = open("scriptPubKey.txt", "w")
    file.write(str(m)+"\n")  # Indicate there are m number of signatures

    for i in range(0, n):
        pvt_keys.append(DSA.generate(1024, domain=params))
        pub_keys.append(pvt_keys[i].y)
        file.write(hex(pub_keys[i]) + "\n")

    file.write(str(n)+"\n")  # Indicate there are n number of public keys
    file.write("OP_CHECKMULTISIG\n")
    file.close()

    # Write signature(s) to scriptSig.txt'
    rnd_pub_keys_idx = random.sample(range(0, n), m)  # The m amount of random pub_keys index
    rnd_pub_keys_idx.sort()

    hash_obj = SHA256.new(message)
    for i in rnd_pub_keys_idx:
        signer = DSS.new(pvt_keys[i], "fips-186-3")
        signatures.append(signer.sign(hash_obj))

    file = open("scriptSig.txt", "wb")
    file.write(b"OP_0\n")  # Dummy

    for i in range(0, len(signatures)):
        file.write(binascii.hexlify(signatures[i]) + b"\n")

    file.close()


if __name__ == "__main__":
    main()
