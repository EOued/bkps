#include "encryption.h"
#include "key_manager.h"
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
  // Checks
  if (sodium_init() < 0) return 1;

  KeyManager* KM = KMInit(10 * 60);
  KMCreateKeys(KM);

  char* plaintext = "Chaotic Neutral, Sugar";
  Data* encrypted = encrypt_data(plaintext, KM);
  printf("Plaintext: %s\n", plaintext);
  printf("Encrypted: [");
  for (size_t i = 0; i < encrypted->size; i++) putc(encrypted->data[i], stdout);
  printf("]\n");
  printf("Decrypted: [");
  Data* decrypted = decrypt_data(encrypted, KM);
  for (size_t i = 0; i < decrypted->size; i++) putc(decrypted->data[i], stdout);
  printf("]\n");
  DataFree(encrypted);
  DataFree(decrypted);
  KMFree(KM);
  return 0;
}
