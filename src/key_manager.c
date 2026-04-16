#include "key_manager.h"
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>

KeyManager* KMInit(size_t validity)
{
  KeyManager* KM;
  if (!(KM = malloc(sizeof(KeyManager))))
    fprintf(stderr, "KeyManager allocation failed");

  KM->validity      = validity;
  KM->private_key   = NULL;
  KM->public_key    = NULL;
  KM->creation_date = time(NULL);
  return KM;
}
void KMFree(KeyManager* KM)
{
  if (!KM) return;
  if (KM->private_key) free(KM->private_key);
  if (KM->public_key) free(KM->public_key);
  free(KM);
}
int KMCreateKeys(KeyManager* KM)
{
  if (KM->private_key) free(KM->private_key);
  if (KM->public_key) free(KM->public_key);
  KM->private_key   = malloc(crypto_box_SECRETKEYBYTES);
  KM->public_key    = malloc(crypto_box_PUBLICKEYBYTES);
  KM->creation_date = time(NULL);
  return crypto_box_keypair(KM->public_key, KM->private_key);
}
