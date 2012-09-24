#include "encrypt.h"

#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>

struct enc_handle
{
    AES_KEY key;
};

void * new_enc_handle(void)
{
    void * handle = malloc(sizeof(struct enc_handle));
    memset(handle, 0, sizeof(struct enc_handle));
    
    return handle;
}

void free_enc_handle(void * handle)
{
    free(handle);
}

void set_key(void * handle, byte_t * key, size_t len)
{
    struct enc_handle * p = (struct enc_handle *) handle;
    byte_t key32[32];
    
    memset(key32, 0, sizeof(key32));

    memcpy(key32, key, len);

    AES_set_encrypt_key(key32, 32*8, &p->key);
}

void encrypt(void * handle, byte_t * buffer, size_t buf_len)
{
    struct enc_handle * p = (struct enc_handle *) handle;
    int num = 0;

    byte_t iv[] = {'s','T','e','e','L',2,0,1,2,9,13,11,12,13,14,15};
    AES_cfb128_encrypt(buffer, buffer, buf_len, &p->key, iv, &num, AES_ENCRYPT);
}


void decrypt(void * handle, byte_t * buffer, size_t buf_len)
{
    struct enc_handle * p = (struct enc_handle *) handle;
    int num = 0;

    byte_t iv[] = {'s','T','e','e','L',2,0,1,2,9,13,11,12,13,14,15};
    AES_cfb128_encrypt(buffer, buffer, buf_len, &p->key, iv, &num, AES_DECRYPT);
}
