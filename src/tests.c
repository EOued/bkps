#include "encryption.h"
#include "key_manager.h"
#include <criterion/criterion.h>
#include <string.h>
#include <unistd.h>

TestSuite(Keys_Success);
Test(Keys_Success, KeyGet_PUBLIC)
{
  KeyManager* KM = KMInit(10);
  KMCreateKeys(KM);
  cr_expect(KMGetKey(KM, PUBLIC) != NULL);
  KMFree(KM);
}

Test(Keys_Success, KeyGet_PRIVATE)
{
  KeyManager* KM = KMInit(10);
  KMCreateKeys(KM);
  cr_expect(KMGetKey(KM, PRIVATE) != NULL);
  KMFree(KM);
}

TestSuite(Keys_Failure);
Test(Keys_Failure, KeyGet_PUBLIC)
{
  KeyManager* KM = KMInit(0);
  KMCreateKeys(KM);
  cr_expect(!KMGetKey(KM, PUBLIC));
  cr_expect(!KM->public_key);
  cr_expect(!KM->private_key);
  KMFree(KM);
}

Test(Keys_Failure, KeyGet_PRIVATE)
{
  KeyManager* KM = KMInit(0);
  KMCreateKeys(KM);
  cr_expect(!KMGetKey(KM, PRIVATE));
  cr_expect(!KM->public_key);
  cr_expect(!KM->private_key);
  KMFree(KM);
}

Test(Keys_Failure, KeyGetWait_PUBLIC)
{
  KeyManager* KM = KMInit(1);
  KMCreateKeys(KM);
  sleep(2);
  cr_expect(!KMGetKey(KM, PUBLIC));
  cr_expect(!KM->public_key);
  cr_expect(!KM->private_key);
  KMFree(KM);
}

Test(Keys_Failure, KeyGetWait_PRIVATE)
{
  KeyManager* KM = KMInit(1);
  KMCreateKeys(KM);
  sleep(2);
  cr_expect(!KMGetKey(KM, PRIVATE));
  cr_expect(!KM->public_key);
  cr_expect(!KM->private_key);
  KMFree(KM);
}

TestSuite(EncryptionSuccess);

Test(EncryptionSuccess, FixedString)
{
  KeyManager* KM = KMInit(10 * 60);
  KMCreateKeys(KM);

  char* plaintext           = "Chaotic Neutral, Sugar";
  Data *plain               = DataFromString(plaintext, 0),
       *encrypted           = encrypt_data(plain, KM, 1),
       *decrypted           = decrypt_data(encrypted, KM, 1);
  char* plaintext_decrypted = DataToString(decrypted, 1);
  cr_expect(strcmp(plaintext, plaintext_decrypted) == 0);
  free(plaintext_decrypted);
  KMFree(KM);
}

void rand_str(char* dest, size_t length)
{
  char charset[] = "0123456789"
                   "abcdefghijklmnopqrstuvwxyz"
                   "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  srand(42);

  while (length-- > 1)
  {
    size_t index = (double)rand() / RAND_MAX * (sizeof charset - 1);
    *dest++      = charset[index];
  }
  *dest = '\0';
}

Test(EncryptionSuccess, RandomString)
{
  KeyManager* KM = KMInit(10 * 60);
  KMCreateKeys(KM);

  char* plaintext = malloc(32);
  rand_str(plaintext, 32);
  Data *plain               = DataFromString(plaintext, 0),
       *encrypted           = encrypt_data(plain, KM, 1),
       *decrypted           = decrypt_data(encrypted, KM, 1);
  char* plaintext_decrypted = DataToString(decrypted, 1);
  cr_expect(strcmp(plaintext, plaintext_decrypted) == 0);
  free(plaintext_decrypted);
  free(plaintext);
  KMFree(KM);
}

TestSuite(EncryptionFailure);

Test(EncryptionFailure, InvalidKey)
{
  KeyManager* KM = KMInit(0);
  KMCreateKeys(KM);

  char* plaintext = "Chaotic Neutral, Sugar";
  Data *plain     = DataFromString(plaintext, 0),
       *encrypted = encrypt_data(plain, KM, 1);
  cr_expect(!encrypted);
  DataFree(encrypted);
  KMFree(KM);
}

Test(EncryptionFailure, ModifiedEncrypted)
{
  KeyManager* KM = KMInit(10 * 60);
  KMCreateKeys(KM);

  char* plaintext           = "Chaotic Neutral, Sugar";
  char* othertext           = "Chaotic neutral, Sugar";
  Data *plain               = DataFromString(othertext, 0),
       *encrypted           = encrypt_data(plain, KM, 1);
  Data* decrypted           = decrypt_data(encrypted, KM, 1);
  char* plaintext_decrypted = DataToString(decrypted, 1);
  cr_expect(strcmp(plaintext, plaintext_decrypted));
  free(plaintext_decrypted);
  KMFree(KM);
}
