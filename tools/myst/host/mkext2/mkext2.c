#define _GNU_SOURCE
#include <assert.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <myst/eraise.h>
#include <myst/file.h>
#include <myst/fssig.h>
#include <myst/getopt.h>
#include <myst/hex.h>
#include <myst/paths.h>
#include <myst/sha256.h>
#include <myst/strings.h>
#include <oeprivate/rsa.h>
#include "../utils.h"

typedef enum _oe_result
{
    OE_OK = 0,
} oe_result_t;

static bool _trace = false;

#define USAGE \
    "\n\
Usage: %s %s [options] <directory> <disk-image>\n\
\n\
Synopsis:\n\
    This tool converts a directory into an ext2 disk image. The image is\n\
    integrity-protected by appending a hash tree. The image may also be\n\
    encrypted (--encrypt) and/or digitally signed (--sign). This tool\n\
    employs standard Linux tools so that the image may be mounted by\n\
    Linux as well as Mystikos.\n\
\n\
Examples:\n\
    $ %s %s <dir> <image>\n\
    $ %s %s --encrypt=<keyfile> <dir> <image>\n\
    $ %s %s --encrypt=<keyfile> --sign=<pubkey>:<privkey> <dir> <image>\n\
\n\
    These examples respectively generate the following disk image layouts.\n\
\n\
    [EXT2|HASH-TREE|FSSIG]\n\
    [LUKS1-HEADERS|ENCRYPTED-EXT2|HASH-TREE|FSSIG]\n\
    [LUKS1-HEADERS|ENCRYPTED-EXT2|HASH-TREE|FSSIG]\n\
\n\
Options:\n\
    -h, --help                  Print this help message\n\
    --size=<size>               Size of the image in bytes\n\
    --encrypt=<keyfile>         Encrypt image with the given binary key file\n\
    --passphrase=<keystr>       Add LUKS key slot with this passphrase\n\
    --sign=<pubkey:privkey>     Sign image with public and private key (PEM)\n\
    --force                     Overwrite existing disk image without asking\n\
    --trace                     Enable tracing\n\
\n"

static void _print_usage(const char* arg0, const char* arg1)
{
    printf(USAGE, arg0, arg1, arg0, arg1, arg0, arg1, arg0, arg1);
}

static int _getopt(
    int* argc,
    const char* argv[],
    const char* opt,
    const char** optarg)
{
    char err[128];
    int ret;

    ret = myst_getopt(argc, argv, opt, optarg, err, sizeof(err));

    if (ret < 0)
        _err("%s", err);

    return ret;
}

#define MIN_PASSPHRASE_LENGTH 14

static void _rtrim(char* str)
{
    char* p = str + strlen(str);

    while (p != str && isspace(p[-1]))
        *--p = '\0';
}

static void _execf(char* buf, size_t buf_size, const char* fmt, ...)
{
    FILE* is;
    char* cmd;
    va_list ap;

    memset(buf, 0, buf_size);

    va_start(ap, fmt);
    if (vasprintf(&cmd, fmt, ap) < 0)
        _err("out of memory");
    va_end(ap);

    if (_trace)
        printf("command: %s\n", cmd);

    if (!(is = popen(cmd, "r")))
        _err("popen() failed: %s", cmd);

    if (!fgets(buf, buf_size, is))
        _err("popen() failed to read output: %s", cmd);

    _rtrim(buf);

    if (pclose(is) != 0)
        _err("pclose() failed: %s", cmd);

    free(cmd);
}

static void _calculate_required_image_size(const char* dirname, size_t* size)
{
    char buf[64];
    size_t n;
    char* end;
    const size_t mb = 1048576;
    const size_t nmb = 8;
    const size_t min_size = nmb * mb;

    _execf(buf, sizeof(buf), "du -b -c -s %s | grep total | cut -f 1", dirname);

    n = strtoul(buf, &end, 10);

    if (!end || *end || n == 0)
        _err("unexpected failure when calculating image size");

    /* round size to next mb multiple */
    n = (n + mb - 1) / mb * mb;

    /* increase size by 50% */
    n += (n / 2);

    /* set n to the minimum image size */
    if (n < min_size)
        n = min_size;

    *size = n;
}

__attribute__((format(printf, 1, 2))) static void _systemf(const char* fmt, ...)
{
    char* cmd;
    va_list ap;

    va_start(ap, fmt);
    if (vasprintf(&cmd, fmt, ap) < 0)
        _err("out of memory");
    va_end(ap);

    if (_trace)
        printf("command: %s\n", cmd);

    if (system(cmd) != 0)
        _err("failed to execute command: %s", cmd);

    free(cmd);
}

static void _create_zero_filled_image(const char* path, size_t size)
{
    int fd = 0;
    static uint8_t _block[1024];

    if (size < sizeof(_block))
        _err("image size too small: %s: %zu", path, sizeof(_block));

    if ((fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0640)) < 0)
        _err("failed to open file for write: %s", path);

    if (lseek(fd, size - sizeof(_block), SEEK_SET) < 0)
        _err("failed to seek file: %s: %zu", path, size);

    if (write(fd, _block, sizeof(_block)) != sizeof(_block))
        _err("failed to write file: %s", path);

    close(fd);

    /* set the owner of this file to the sudo user if defined */
    if (myst_chown_sudo_user(path) != 0)
        _err("failed to chown to sudo user: %s", path);
}

static void _create_ext2_image(
    const char* dirname,
    const char* image,
    size_t size)
{
    /* create a zero-filled image with holes */
    _create_zero_filled_image(image, size);

    // format as an EXT2 image and copy the contents of the given directory
    // into the root directory of the image
    _systemf("/sbin/mke2fs -q %s -d %s", image, dirname);
}

static void _create_luks_image(
    const char* dirname,
    const char* image,
    size_t size,
    const char* key_file,
    const char* passphrase)
{
    char passphrase_buf[128];
    bool remove_passphrase = false;
    const size_t keybytes = 64;
    const size_t keybits = 512;
    struct stat st;
    char tmpfile[] = "/tmp/mystXXXXXX";
    const char* dmname;
    char dmpath[PATH_MAX];
    char mntdir[] = "/tmp/mystXXXXXX";

    /* if no --passphrase option, then generate one */
    if (!passphrase)
    {
        _execf(
            passphrase_buf,
            sizeof(passphrase_buf),
            "head -c 32 /dev/urandom | hexdump -v -e '/1 \"%%02x\"'");

        passphrase = passphrase_buf;
        remove_passphrase = true;
    }

    /* check whether masterkey file exists */
    if (stat(key_file, &st) != 0)
        _err("key file not found: %s", key_file);

    /* check the size of the masterkey file */
    if (st.st_size != keybytes)
        _err("master key file must be %zu bytes", keybytes);

    /* create a zero-filled image */
    _systemf("/usr/bin/head -c %zu /dev/zero > %s", size, image);

    /* set the owner of this file to the sudo user if defined */
    if (myst_chown_sudo_user(image) != 0)
        _err("failed to chown to sudo user: %s", image);

    /* do luksFormat on image */
    _systemf(
        "/bin/echo %s | /sbin/cryptsetup luksFormat "
        "--type luks1 "
        "--key-size=%zu "
        "--cipher=aes-xts-plain64 "
        "--master-key-file=%s "
        "%s --key-file=-",
        passphrase,
        keybits,
        key_file,
        image);

    /* find the dev-mapper name for opening the LUKS device */
    {
        int fd;

        if ((fd = mkstemp(tmpfile)) < 0)
            _err("failed to create temporary file name");

        close(fd);
        unlink(tmpfile);

        dmname = myst_basename(tmpfile);
        snprintf(dmpath, sizeof(dmpath), "/dev/mapper/%s", dmname);
    }

    _systemf(
        "/bin/echo %s | /sbin/cryptsetup luksOpen --key-file=- %s %s",
        passphrase,
        image,
        dmname);

    /* format the ext2 file system */
    _systemf("/sbin/mke2fs -q %s", dmpath);

    /* create the mount directory */
    if (!mkdtemp(mntdir))
        _err("failed to create temporary directory");

    /* mount the directory */
    _systemf("/bin/mount %s %s", dmpath, mntdir);

    /* copy the directory into the mounted ext2 file system */
    _systemf("/bin/tar c -C %s -f - .|/bin/tar x -C %s -f -", dirname, mntdir);

    /* unmount the ext2 image */
    _systemf("/bin/umount %s", mntdir);

    /* remove the passphrase (if generated) */
    if (remove_passphrase)
    {
        _systemf(
            "echo %s | /sbin/cryptsetup luksRemoveKey %s --key-file=-",
            passphrase,
            image);
    }

    /* close the luks device */
    _systemf("/sbin/cryptsetup luksClose %s", dmname);
}

static void _append_hash_tree(
    const char* image,
    size_t size,
    myst_sha256_t* root_hash)
{
    struct stat st;
    char buf[256];
    ssize_t n;

    if (stat(image, &st) != 0)
        _err("unexpected: image does not exist: %s", image);

    if (st.st_size != size)
        _err("unexpected: image size mismatch: %zu/%zu\n", st.st_size, size);

    _execf(
        buf,
        sizeof(buf),
        "veritysetup format --hash-offset=%zu %s %s | "
        "grep '^Root hash:' | sed 's/Root hash:[\\t ]*//g'",
        size,
        image,
        image);

    if ((n = myst_ascii_to_bin(buf, root_hash->data, sizeof(*root_hash))) < 0)
        _err("malformed root hash: %s", buf);
}

static int _sign(
    const char* image,
    const char* pubkey_path,
    const char* privkey_path,
    size_t image_size,
    const myst_sha256_t* root_hash)
{
    void* pubkey = NULL;
    size_t pubkey_size = 0;
    void* privkey = NULL;
    size_t privkey_size = 0;
    uint8_t signature[MYST_MAX_SIGNATURE_SIZE];
    size_t signature_size = sizeof(signature);
    myst_sha256_t signer_hash;
    myst_fssig_t fssig;

    (void)pubkey_size;
    (void)privkey_size;

    memset(&signer_hash, 0, sizeof(myst_sha256_t));
    memset(&signature, 0, MYST_MAX_SIGNATURE_SIZE);

    /* sign the root hash */
    if (privkey_path)
    {
        oe_rsa_private_key_t key = {0};

        /* load the private key */
        if (myst_load_file(privkey_path, &privkey, &privkey_size) != 0)
            _err("failed to load private key: %s", privkey_path);

        if (oe_rsa_private_key_read_pem(
                &key, (const uint8_t*)privkey, privkey_size + 1) != OE_OK)
        {
            _err("failed to read private key: %s", privkey_path);
        }

        if (oe_rsa_private_key_sign(
                &key,
                OE_HASH_TYPE_SHA256,
                root_hash->data,
                sizeof(myst_sha256_t),
                signature,
                &signature_size) != OE_OK)
        {
            _err("signing operation failed: %s", privkey_path);
        }

        if (signature_size > MYST_MAX_SIGNATURE_SIZE)
            _err("unexpected: signature is too big: %zu\n", signature_size);

        oe_rsa_private_key_free(&key);
    }

    /* get the sha256 hash of the modulus (the signer hash) */
    if (pubkey_path)
    {
        oe_rsa_public_key_t key = {0};
        uint8_t modulus[4096];
        size_t modulus_size = sizeof(modulus);

        /* load the public key */
        if (myst_load_file(pubkey_path, &pubkey, &pubkey_size) != 0)
            _err("failed to load public key: %s", pubkey_path);

        if (oe_rsa_public_key_read_pem(
                &key, (const uint8_t*)pubkey, pubkey_size + 1) != 0)
        {
            return -1;
        }

        if (oe_rsa_public_key_get_modulus(&key, modulus, &modulus_size) != 0)
            _err("failed to get modulus from public key: %s", pubkey_path);

        /* compute the hash of the public key */
        if (myst_sha256(&signer_hash, modulus, modulus_size) != 0)
            _err("unexpected: failed to compute hash");
    }

    if (_trace)
    {
        printf("hashoffset=%zu\n", image_size);

        printf("signer=");
        myst_hexdump(NULL, &signer_hash, sizeof(myst_sha256_t));

        printf("signature=");
        myst_hexdump(NULL, signature, signature_size);

        printf("roothash=");
        myst_hexdump(NULL, root_hash, sizeof(myst_sha256_t));
    }

    /* Initialize the FSSIG structure */
    {
        memset(&fssig, 0, sizeof(myst_fssig_t));
        fssig.magic = MYST_FSSIG_MAGIC;
        fssig.version = MYST_FSSIG_VERSION;
        fssig.hash_offset = image_size;
        memcpy(&fssig.root_hash, root_hash, sizeof(fssig.root_hash));

        if (pubkey_path && privkey_path)
        {
            memcpy(&fssig.signer, signer_hash.data, sizeof(fssig.signer));
            memcpy(&fssig.signature, signature, signature_size);
            fssig.signature_size = signature_size;
        }
    }

    /* append the FSSIG to the image */
    {
        int fd;

        if ((fd = open(image, O_WRONLY | O_CREAT, 0640)) < 0)
            _err("failed to open file for write: %s", image);

        if (lseek(fd, 0, SEEK_END) < 0)
            _err("cannot seek end of file: %s", image);

        if (write(fd, &fssig, sizeof(fssig)) != sizeof(fssig))
            _err("cannot write signature: %s", image);

        close(fd);
    }

    free(privkey);

    return 0;
}

int mkext2_action(int argc, const char* argv[])
{
    bool help = false;
    bool luks = false;
    bool force = false;
    const char* key_file = NULL;
    const char* passphrase = NULL;
    const char* size_opt = NULL;
    size_t size = 0;
    struct stat st;
    const size_t mb = 1048576;
    const size_t nmb = 8;
    const size_t min_size = nmb * mb;
    myst_sha256_t root_hash;
    const char* sign = NULL;
    const char* pubkey = NULL;
    const char* privkey = NULL;

    /* get the --help option */
    if (_getopt(&argc, argv, "--help", NULL) == 0 ||
        _getopt(&argc, argv, "-h", NULL) == 0)
    {
        help = true;
    }

    /* get the --trace option */
    if (_getopt(&argc, argv, "--trace", NULL) == 0 ||
        _getopt(&argc, argv, "-t", NULL) == 0)
    {
        _trace = true;
    }

    /* get the --luks option */
    if (_getopt(&argc, argv, "--encrypt", &key_file) == 0 ||
        _getopt(&argc, argv, "-e", &key_file) == 0)
    {
        luks = true;
    }

    if (luks && geteuid() != 0)
        _err("mkext2 --encrypt option requires root privileges");

    /* get the --force option */
    if (_getopt(&argc, argv, "--force", NULL) == 0 ||
        _getopt(&argc, argv, "-f", NULL) == 0)
    {
        force = true;
    }

    /* get the --passphrase */
    if (_getopt(&argc, argv, "--passphrase", &passphrase) == 0 ||
        _getopt(&argc, argv, "-p", &passphrase) == 0)
    {
        const size_t min_len = 14;

        if (strlen(passphrase) < min_len)
            _err("--passphrase option length must be >= %zu", min_len);
    }

    /* get the --sign option */
    if (_getopt(&argc, argv, "--sign", &sign) == 0 ||
        _getopt(&argc, argv, "-s", &sign) == 0)
    {
        char* colon;

        if (!(colon = strchr(sign, ':')))
            _err("malformed --sign option: missing ':' delimiter");

        *colon = '\0';
        pubkey = sign;
        privkey = colon + 1;

        assert(myst_validate_file_path(pubkey));
        assert(myst_validate_file_path(privkey));
    }

    /* get the --size option */
    if (_getopt(&argc, argv, "--size", &size_opt) == 0)
    {
        char* end = NULL;
        size = strtoul(size_opt, &end, 10);

        if (!end || *end)
            _err("bad --size option argument");

        if (size < min_size)
            _err("--size must be at least %zu mbs", nmb);
    }

    if (help || argc != 4)
    {
        _print_usage(argv[0], argv[1]);
        exit(0);
    }

    const char* dirname = argv[2];
    const char* image = argv[3];

    /* verify that directory exists */
    if (stat(dirname, &st) != 0 || !S_ISDIR(st.st_mode))
        _err("no such directory: %s", dirname);

    /* fail if image already exists and no --force option */
    if (!force && stat(image, &st) == 0)
        _err("%s already exists: cautiously use --force to override", image);

    /* calculate the minimum required size */
    {
        size_t n;

        _calculate_required_image_size(dirname, &n);

        if (n > size)
            size = n;
    }

    if (luks)
    {
        _create_luks_image(dirname, image, size, key_file, passphrase);
    }
    else
    {
        _create_ext2_image(dirname, image, size);
    }

    assert(myst_validate_file_path(image));
    _append_hash_tree(image, size, &root_hash);

    _sign(image, pubkey, privkey, size, &root_hash);

    return 0;
}

static bool _is_zero_filled(const void* s, size_t n)
{
    const uint8_t* p = s;

    while (n--)
    {
        if (*p++)
            return false;
    }

    return true;
}

#define FSSIG_USAGE \
    "\n\
Usage: %s %s [options] <ext2-disk-image>\n\
\n\
Synopsis:\n\
    This tool dumps the contents of the file-system signature structure\n\
    (FSSIG) appended to EXT2 images that are generated by the 'myst mkext2'\n\
    command. The FSSIG contains the roothash of the EXT2 image and the\n\
    digital signature if any (see the 'myst mkext2 --sign option).\n\
\n\
Options:\n\
    -h, --help                  Print this help message\n\
    --roothash                  Print only the roothash\n\
\n"

int fssig_action(int argc, const char* argv[])
{
    const char* color = "";
    const char* reset = "";
    myst_fssig_t fssig;
    bool roothash = false;
    bool help = false;

    /* get the --roothash option */
    if (_getopt(&argc, argv, "--roothash", NULL) == 0)
        roothash = true;

    /* get the --help option */
    if (_getopt(&argc, argv, "--help", NULL) == 0 ||
        _getopt(&argc, argv, "-h", NULL) == 0)
    {
        help = true;
    }

    if (help)
    {
        printf(FSSIG_USAGE, argv[0], argv[1]);
        exit(0);
    }

    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s %s <image>\n", argv[0], argv[1]);
        exit(1);
    }

    if (isatty(STDOUT_FILENO))
    {
        color = "\e[32m"; /* green */
        reset = "\e[0m";  /* reset */
    }

    const char* image = argv[2];

    if (myst_load_fssig(image, &fssig) != 0)
        _err("image does not have the fssig trailer: %s", image);

    if (roothash)
    {
        myst_hexdump(NULL, fssig.root_hash, sizeof(fssig.root_hash));
    }
    else
    {
        printf("\n");
        printf("=== File-system signature (FSSIG):\n");
        printf("%smagic%s=%016lx\n", color, reset, fssig.magic);
        printf("%sversion%s=%lu\n", color, reset, fssig.version);
        printf("%shash_offset%s=%lu\n", color, reset, fssig.hash_offset);

        printf("%sroot_hash%s=", color, reset);
        myst_hexdump(NULL, fssig.root_hash, sizeof(fssig.root_hash));

        if (_is_zero_filled(fssig.signer, sizeof(fssig.signer)))
        {
            printf("%ssigner%s=null\n", color, reset);
        }
        else
        {
            printf("%ssigner%s=", color, reset);
            myst_hexdump(NULL, fssig.signer, sizeof(fssig.signer));
        }

        if (_is_zero_filled(fssig.signature, sizeof(fssig.signature)))
        {
            printf("%ssignature%s=null\n", color, reset);
        }
        else
        {
            printf("%ssignature%s=", color, reset);
            myst_hexdump(NULL, fssig.signature, fssig.signature_size);
        }

        printf("%ssignature_size%s=%lu\n", color, reset, fssig.signature_size);

        printf("\n");
    }

    return 0;
}
