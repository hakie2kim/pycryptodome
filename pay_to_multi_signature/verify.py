from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import binascii

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

message = b"CSCI301 Contemporary Topics in Security 2023"


def main():
    # Reading scriptSig.txt and pushing into stacks
    file = open("scriptSig.txt", "rb")
    file.readline()  # Skip a dummy value, "OP_0"
    stack = file.read().splitlines()
    file.close()

    # Reading scriptPubKey.txt and pushing into stacks
    file = open("scriptPubKey.txt", "r")

    script_pub_key = file.read().splitlines()
    m = int(script_pub_key[0])  # The number of signatures should be the first of scriptPubKey
    n = int(script_pub_key[-2])  # The number of public keys should be the second last of scriptPubKey

    stack += script_pub_key[0: -1]  # Exclude a string "OP_CHECKMULTISIG"

    file.close()

    print("After all elements are pushed to a stack ...")
    print(stack)
    print()

    # Checking multi signatures
    pub_keys = []
    signatures = []

    for i in range(0, n+1):
        pub_keys.append(stack.pop())

    for i in range(0, m+1):
        signatures.append(stack.pop())

    print("After all elements are popped from the stack ...")
    print("Stack =", stack)
    print()

    # Verifying public keys with signature
    tally = 0

    hash_obj = SHA256.new(message)
    k = 1  # range starts from 1 to ignore the number of public keys and signatures
    for i in range(1, m+1):  # Signatures
        for j in range(k, n+1):  # Public keys
            try:
                pub_key_y = int(pub_keys[j], 16)
                params = [pub_key_y, param_key.g, param_key.p, param_key.q]
                pub_key = DSA.construct(params)

                verifier = DSS.new(pub_key, "fips-186-3")
                verifier.verify(hash_obj, binascii.unhexlify(signatures[i]))

                print("Verifying pub_key_" + str(j) + " with sig_" + str(i) + "...")
                print("Valid signature\n")
                tally += 1
                k += 1
                break  # Go to a next signature to verify

            except ValueError:
                print("Verifying pub_key_" + str(j) + " with sig_" + str(i) + "...")
                print("Invalid signature\n")
                k += 1

    if tally == m:
        print("The tally of valid signatures (" + str(tally) + ") equals to M and CHECKMULTISIG pushes a 1 to stack ...")
        stack.append(1)
        print("Stack =", stack)
        print("Therefore, the script is valid.")
    else:
        print("As the tally of valid signatures (" + str(tally) + ") does not equal to M, this script is not valid")


if __name__ == "__main__":
    main()
