#ifndef __ENCRYPT_H__
#define __ENCRYPT_H__

#include <sys/types.h>

typedef unsigned char byte_t;

void * new_enc_handle(void);

void free_enc_handle(void * handle);

void set_key(void * handle, byte_t * key, size_t len);

void encrypt(void * handle, byte_t * buffer, size_t buf_len);

void decrypt(void * handle, byte_t * buffer, size_t buf_len);


#endif
