#include "encryption.h"
#include "macros.h"
#include <sodium.h>
#include <stdlib.h>
#include <string.h>

Data* encrypt_data(const char* data, KeyManager* KM)
{
  size_t text_length = strlen(data);
  return encrypt_data_length(data, text_length, KM);
}

Data* encrypt_data_length(const char* data, size_t data_length, KeyManager* KM)
{
  unsigned char *public_key  = KMGetKey(KM, PUBLIC),
                *private_key = KMGetKey(KM, PRIVATE);
  if (!public_key || !private_key) return NULL;

  size_t text_length         = data_length,
         cipher_length       = text_length + crypto_box_MACBYTES;
  unsigned char *cipher_text = malloc(cipher_length),
                *nonce       = malloc(crypto_box_NONCEBYTES);
  Data* encrypted            = malloc(sizeof(Data));

  if (!cipher_text) ERROR("Failed to allocate memory for cipher_text");
  if (!nonce) ERROR("Failed to allocate memory for nonce");
  if (!encrypted) ERROR("Failed to allocate memory for encrypted");

  randombytes_buf(nonce, crypto_box_NONCEBYTES);
  if (crypto_box_easy(cipher_text, (unsigned char*)data, text_length, nonce,
                      public_key, private_key))
  {
    fprintf(stderr, "Data encryption failed");
    encrypted->data = calloc(1, 1);
    encrypted->size = 0;
    if (!encrypted->data) ERROR("Failed to allocate memory for encrypted data");
    goto cleanup;
  }

  encrypted->data = malloc(crypto_box_NONCEBYTES + cipher_length);
  encrypted->size = crypto_box_NONCEBYTES + cipher_length;
  if (!encrypted->data) ERROR("Failed to allocate memory for encrypted data");

  memcpy(encrypted->data, nonce, crypto_box_NONCEBYTES);
  memcpy(encrypted->data + crypto_box_NONCEBYTES, cipher_text, cipher_length);
cleanup:
  FREE(cipher_text);
  FREE(nonce);
  return encrypted;
}

void DataFree(Data* encrypted)
{
  if (!encrypted) return;
  FREE(encrypted->data);
  free(encrypted);
  return;
}

Data* decrypt_data(Data* encrypted, KeyManager* KM)
{
  unsigned char *public_key  = KMGetKey(KM, PUBLIC),
                *private_key = KMGetKey(KM, PRIVATE);
  if (!public_key || !private_key) return NULL;

  unsigned char *cipher_text = malloc(encrypted->size - crypto_box_NONCEBYTES),
                *nonce       = malloc(crypto_box_NONCEBYTES);
  Data* decrypted            = malloc(sizeof(Data));
  if (!cipher_text) ERROR("Failed to allocate memory for cipher_text");
  if (!nonce) ERROR("Failed to allocate memory for nonce");
  if (!decrypted) ERROR("Failed to allocate memory for encrypted");

  memcpy(nonce, encrypted->data, crypto_box_NONCEBYTES);
  memcpy(cipher_text, encrypted->data + crypto_box_NONCEBYTES,
         encrypted->size - crypto_box_NONCEBYTES);

  decrypted->data =
      malloc(encrypted->size - crypto_box_NONCEBYTES - crypto_box_MACBYTES);
  decrypted->size =
      encrypted->size - crypto_box_NONCEBYTES - crypto_box_MACBYTES;
  if (crypto_box_open_easy(decrypted->data, cipher_text,
                           encrypted->size - crypto_box_NONCEBYTES, nonce,
                           public_key, private_key))
  {
    fprintf(stderr, "Data decryption failed");
    decrypted->data = calloc(1, 1);
    decrypted->size = 0;
  }

  FREE(cipher_text);
  FREE(nonce);
  return decrypted;
}
