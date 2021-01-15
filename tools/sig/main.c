#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <myst/file.h>
#include <myst/hex.h>
#include <myst/sha256.h>
#include <oeprivate/rsa.h>

#define SIG_SIZE 4096

#define HASH_SIZE 32

enum _oe_result
{
    OE_OK = 0,
};

static ssize_t _sign(
    char* private_key,
    const myst_sha256_t* hash,
    uint8_t* signature,
    size_t signature_size)
{
    oe_rsa_private_key_t key = {0};
    size_t private_key_size = strlen(private_key) + 1;

    if (oe_rsa_private_key_read_pem(
            &key, (const uint8_t*)private_key, private_key_size) != OE_OK)
    {
        return -1;
    }

    if (oe_rsa_private_key_sign(
            &key,
            OE_HASH_TYPE_SHA256,
            hash,
            sizeof(myst_sha256_t),
            signature,
            &signature_size) != OE_OK)
    {
        oe_rsa_private_key_free(&key);
        return -1;
    }

    oe_rsa_private_key_free(&key);
    return signature_size;
}

static int _verify(
    char* public_key,
    const myst_sha256_t* hash,
    const uint8_t* signature,
    size_t signature_size)
{
    oe_rsa_public_key_t key = {0};

    if (oe_rsa_public_key_read_pem(
            &key, (const uint8_t*)public_key, strlen(public_key) + 1) != 0)
    {
        return -1;
    }

    if (oe_rsa_public_key_verify(
            &key,
            OE_HASH_TYPE_SHA256,
            hash,
            sizeof(myst_sha256_t),
            signature,
            signature_size) != 0)
    {
        oe_rsa_public_key_free(&key);
        return -1;
    }

    oe_rsa_public_key_free(&key);
    return 0;
}

int _sign_action(int argc, const char* argv[])
{
    void* private_key;
    size_t private_key_size;
    ssize_t n;
    uint8_t hash[HASH_SIZE];
    uint8_t sig[SIG_SIZE];
    myst_sha256_t sha256;

    if (argc != 4)
    {
        fprintf(stderr, "Usage: %s sign <private-key> <hash>\n", argv[0]);
        exit(1);
    }

    /* load the private key */
    if (myst_load_file(argv[2], &private_key, &private_key_size) != 0)
    {
        fprintf(stderr, "%s: failed to load %s\n", argv[0], argv[2]);
        exit(1);
    }

    /* convert the hash argument to binary */
    if ((n = myst_ascii_to_bin(argv[3], hash, sizeof(hash))) < 0)
    {
        fprintf(stderr, "%s: bad hash argument: %s\n", argv[0], argv[3]);
        exit(1);
    }

    /* verify that the hash is the size of a SHA-256 hash */
    if (n != sizeof(myst_sha256_t))
    {
        fprintf(stderr, "%s: hash too short: %s\n", argv[0], argv[3]);
        exit(1);
    }

    memcpy(&sha256, hash, sizeof(sha256));

    if ((n = _sign(private_key, &sha256, sig, sizeof(sig))) < 0)
    {
        fprintf(stderr, "%s: sign failed\n", argv[0]);
        exit(1);
    }

    free(private_key);

    myst_hexdump(NULL, sig, n);

    return 0;
}

int _verify_action(int argc, const char* argv[])
{
    void* public_key;
    size_t public_key_size;
    ssize_t n;
    uint8_t hash[HASH_SIZE];
    myst_sha256_t sha256;
    uint8_t sig[SIG_SIZE];

    if (argc != 5)
    {
        fprintf(
            stderr,
            "Usage: %s verify <public-key> <hash> <signature>\n",
            argv[0]);
        exit(1);
    }

    /* load the public key */
    if (myst_load_file(argv[2], &public_key, &public_key_size) != 0)
    {
        fprintf(stderr, "%s: failed to load %s\n", argv[0], argv[2]);
        exit(1);
    }

    /* convert the hash argument to binary */
    if ((n = myst_ascii_to_bin(argv[3], hash, sizeof(hash))) < 0)
    {
        fprintf(stderr, "%s: bad hash argument: %s\n", argv[0], argv[3]);
        exit(1);
    }

    /* verify that the hash is the size of a SHA-256 hash */
    if (n != sizeof(myst_sha256_t))
    {
        fprintf(stderr, "%s: hash too short: %s\n", argv[0], argv[3]);
        exit(1);
    }

    memcpy(&sha256, hash, sizeof(sha256));

    /* convert the signature argument to binary */
    if ((n = myst_ascii_to_bin(argv[4], sig, sizeof(sig))) < 0)
    {
        fprintf(stderr, "%s: bad hash argument: %s\n", argv[0], argv[3]);
        exit(1);
    }

    /* verify the signature of the hash */
    if (_verify(public_key, &sha256, sig, n) != 0)
    {
        fprintf(stderr, "%s: verify failed\n", argv[0]);
        exit(1);
    }

    free(public_key);

    printf("verify okay\n");

    return 0;
}

int _signer_action(int argc, const char* argv[])
{
    void* public_key;
    size_t public_key_size;
    oe_rsa_public_key_t key;
    uint8_t buf[4096];
    size_t buf_size = sizeof(buf);
    myst_sha256_t sha256;

    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s verify <public-key>\n", argv[0]);
        exit(1);
    }

    /* load the public key */
    if (myst_load_file(argv[2], &public_key, &public_key_size) != 0)
    {
        fprintf(stderr, "%s: failed to load %s\n", argv[0], argv[2]);
        exit(1);
    }

    if (oe_rsa_public_key_read_pem(
            &key, (const uint8_t*)public_key, strlen(public_key) + 1) != 0)
    {
        return -1;
    }

    if (oe_rsa_public_key_get_modulus(&key, buf, &buf_size) != 0)
    {
        fprintf(stderr, "%s: failed to get modulus\n", argv[0]);
        exit(1);
    }

    /* compute the hash of the public key */
    if (myst_sha256(&sha256, buf, buf_size) != 0)
    {
        fprintf(stderr, "%s: hashing failed\n", argv[0]);
        exit(1);
    }

    myst_hexdump(NULL, sha256.data, sizeof(sha256));

    free(public_key);
    oe_rsa_public_key_free(&key);

    return 0;
}

int main(int argc, const char* argv[])
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <action> ...\n", argv[0]);
        exit(1);
    }

    if (strcmp(argv[1], "sign") == 0)
    {
        return _sign_action(argc, argv);
    }
    else if (strcmp(argv[1], "verify") == 0)
    {
        return _verify_action(argc, argv);
    }
    else if (strcmp(argv[1], "signer") == 0)
    {
        return _signer_action(argc, argv);
    }
    else
    {
        fprintf(stderr, "%s: unknown action: %s\n", argv[0], argv[1]);
        exit(1);
    }

    return 0;
}
