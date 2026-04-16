#include "key_manager.h"
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>

int encrypt_file(const char* infile, const char* outfile,
                 unsigned char* public_key, unsigned char* private_key)
{
  FILE* fi = fopen(infile, "rb");
  FILE* fo = fopen(outfile, "wb");

  // Size of fi
  fseek(fi, 0, SEEK_END);
  long len = ftell(fi);
  rewind(fi);

  // File content
  unsigned char* plaintext = malloc(len);
  fread(plaintext, 1, len, fi);

  // Generate nonce (number used once): random number generated to be sure that
  // the cyphertext is different.
  unsigned char nonce[crypto_box_NONCEBYTES];
  randombytes_buf(nonce, sizeof(nonce));

  unsigned char* ciphertext = malloc(len + crypto_box_MACBYTES);

  int _ = crypto_box_easy(ciphertext, plaintext, len, nonce, public_key,
                          private_key);
  (void)_;

  fwrite(nonce, 1, sizeof(nonce), fo);
  fwrite(ciphertext, 1, len + crypto_box_MACBYTES, fo);

  fclose(fi);
  fclose(fo);
  free(plaintext);
  free(ciphertext);
  return 0;
}

int decrypt_file(const char* infile, const char* outfile,
                 unsigned char* sender_pk, unsigned char* receiver_sk)
{

  FILE* fi = fopen(infile, "rb");
  FILE* fo = fopen(outfile, "wb");

  fseek(fi, 0, SEEK_END);
  long len = ftell(fi);
  rewind(fi);

  unsigned char nonce[crypto_box_NONCEBYTES];
  fread(nonce, 1, sizeof nonce, fi);

  long clen                 = len - crypto_box_NONCEBYTES;
  unsigned char* ciphertext = malloc(clen);
  fread(ciphertext, 1, clen, fi);

  unsigned char* plaintext = malloc(clen - crypto_box_MACBYTES);

  if (crypto_box_open_easy(plaintext, ciphertext, clen, nonce, sender_pk,
                           receiver_sk) != 0)
  {
    printf("Decryption failed!\n");
    return -1;
  }

  fwrite(plaintext, 1, clen - crypto_box_MACBYTES, fo);

  fclose(fi);
  fclose(fo);
  free(ciphertext);
  free(plaintext);

  return 0;
}

int main()
{
  // Checks
  if (sodium_init() < 0) return 1;

  KeyManager* KM = KMInit(10 * 60);
  KMCreateKeys(KM);
  char* FILE = "test.txt";
  encrypt_file(FILE, "fileout", KM->public_key, KM->private_key);
  decrypt_file("fileout", "out.txt", KM->public_key, KM->private_key);
  KMFree(KM);
  return 0;
}
