#include "key_manager.h"
#include "macros.h"
#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

KeyManager* KMInit(size_t validity)
{

  KeyManager* KM;
  if (!(KM = malloc(sizeof(KeyManager)))) ERROR("KeyManager allocation failed");

  KM->validity    = validity;
  KM->private_key = NULL;
  KM->public_key  = NULL;
  clock_gettime(CLOCK_MONOTONIC, &KM->creation_date);
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
  clock_gettime(CLOCK_MONOTONIC, &KM->creation_date);
  return crypto_box_keypair(KM->public_key, KM->private_key);
}

unsigned char* KMGetKey(KeyManager* KM, enum KEY_TYPE kt)
{
  struct timespec current;
  clock_gettime(CLOCK_MONOTONIC, &current);

  struct timespec diff;
  diff.tv_sec  = current.tv_sec - KM->creation_date.tv_sec;
  diff.tv_nsec = current.tv_nsec - KM->creation_date.tv_nsec;

  uint64_t diff_ns     = 1000000000ULL * diff.tv_sec + diff.tv_nsec;
  uint64_t validity_ns = KM->validity * 1000000000ULL;
  if (diff_ns > validity_ns)
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
