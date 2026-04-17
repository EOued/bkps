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

  char* plaintext           = "Chaotic Neutral, Sugar";
  Data *plain               = DataFromString(plaintext, 0),
       *encrypted           = encrypt_data(plain, KM, 1),
       *decrypted           = decrypt_data(encrypted, KM, 1);
  char* plaintext_decrypted = DataToString(decrypted, 1);
  printf("Plaintext: %s\n", plaintext);
  printf("Plaintext decrypted: %s\n", plaintext_decrypted);
  free(plaintext_decrypted);
  KMFree(KM);
  return 0;
}
