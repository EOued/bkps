#include "key_manager.h"
#include "macros.h"
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>

KeyManager* KMInit(size_t validity)
{
  KeyManager* KM;
  if (!(KM = malloc(sizeof(KeyManager)))) ERROR("KeyManager allocation failed");

  KM->validity      = validity;
  KM->private_key   = NULL;
  KM->public_key    = NULL;
  KM->creation_date = time(NULL);
  return KM;
}
void KMFree(KeyManager* KM)
{
  if (!KM) return;
  FREE(KM->private_key);
  FREE(KM->public_key);
  free(KM);
}
int KMCreateKeys(KeyManager* KM)
{
  FREE(KM->private_key);
  FREE(KM->public_key);
  KM->private_key = malloc(crypto_box_SECRETKEYBYTES);
  KM->public_key  = malloc(crypto_box_PUBLICKEYBYTES);
  if (!KM->private_key) ERROR("Failed to allocate private key");
  if (!KM->public_key) ERROR("Failed to allocate public key");
  KM->creation_date = time(NULL);
  return crypto_box_keypair(KM->public_key, KM->private_key);
}
unsigned char* KMGetKey(KeyManager* KM, enum KEY_TYPE kt)
{
  if (KM->creation_date + KM->validity < (size_t)time(NULL))
  {
    FREE(KM->private_key);
    FREE(KM->public_key);
    KM->private_key = NULL;
    KM->public_key  = NULL;
    return NULL;
  }
  unsigned char* key = kt == PUBLIC ? KM->public_key : KM->private_key;
  return key;
}
