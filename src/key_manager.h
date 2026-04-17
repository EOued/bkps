#ifndef KEY_MANAGER
#define KEY_MANAGER

#include <time.h>

// Manage keys (and their validity time)

enum KEY_TYPE
{
  PUBLIC,
  PRIVATE
};

typedef struct
{
  // In seconds
  size_t validity;

  // Keys storage
  unsigned char* private_key;
  unsigned char* public_key;
  struct timespec creation_date;
} KeyManager;

KeyManager* KMInit(size_t validity);
void KMFree(KeyManager* KM);
int KMCreateKeys(KeyManager* KM);
unsigned char* KMGetKey(KeyManager* KM, enum KEY_TYPE kt);

#endif
