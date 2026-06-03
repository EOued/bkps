#include "encryption.h"
#include "keepass_reader.h"
#include "key_manager.h"
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "macros.h"

int main(void)
{
  FILE* f   = fopen("test.kdbx", "rb");
  header* h = read_header(f);
  keys* k   = compute_keys(h);
  free(HMAC_SHA_256_HASH_KEY(k, 3));
  free_header(h);
  FREE(k);
  fclose(f);
}
