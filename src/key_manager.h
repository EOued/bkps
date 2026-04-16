#ifndef KEY_MANAGER
#define KEY_MANAGER

#include <time.h>

// Manage keys (and their validity time)

typedef struct
{
  size_t validity; // How long is a key valid

  // Keys storage
  unsigned char* private_key;
  unsigned char* public_key;
  time_t creation_date;
} KeyManager;

KeyManager* KMInit(size_t validity);
void KMFree(KeyManager* KM);
int KMCreateKeys(KeyManager* KM);

#endif
