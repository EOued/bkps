#include "encryption.h"
#include "keepass_reader.h"
#include "key_manager.h"
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "macros.h"

int main(void)
{
  int EXIT_CODE = 0;
  FILE* f       = fopen("test.kdbx", "rb");
  header* h     = read_header(f);

  long pos = ftell(f);
  if (pos == -1)
  {
    perror("ftell");
    EXIT_CODE = 1;
    goto end1;
  }

  unsigned char* raw_header = malloc(pos);
  MCHK(raw_header);
  rewind(f);
  fread(raw_header, pos, 1, f);

  unsigned char header_hash[32];
  fread(header_hash, 32, 1, f);
  unsigned char cheader_hash[32];
  SHA256(raw_header, pos, cheader_hash);
  if (memcmp(cheader_hash, header_hash, 32))
  {
    fprintf(stderr, "Failed to validate error: File is corrupted.\n");
    EXIT_CODE = 1;
    goto end2;
  }

  keys* k = compute_keys(h);
  unsigned char CHMAP_SHA_256_HASH[32];
  HMAC(EVP_sha256(), k->hmac_header_key, 64, raw_header, pos,
       CHMAP_SHA_256_HASH, NULL);
  unsigned char HMAP_SHA_256_HASH[32];
  fread(HMAP_SHA_256_HASH, 32, 1, f);
  if (memcmp(HMAP_SHA_256_HASH, CHMAP_SHA_256_HASH, 32))
  {
    fprintf(stderr, "Failed to validate error: Either the password is wrong or "
                    "the file is corrupted.\n");
    EXIT_CODE = 1;
    goto end3;
  }
  /* // Hexdump of remaining of file */
  /* int byte; */
  /* while (1) */
  /* { */
  /*   for (int _ = 0; _ < 8; _++) */
  /*   { */
  /*     byte = fgetc(f); */
  /*     if (byte == EOF) goto end; */
  /*     printf("%02x", byte); */
  /*     byte = fgetc(f); */
  /*     if (byte == EOF) goto end; */
  /*     printf("%02x ", byte); */
  /*   } */
  /*   printf("\n"); */
  /* } */
  /* printf("\n"); */
end3:
  FREE(k);
end2:
  FREE(raw_header);
end1:
  fclose(f);
  free_header(h);
  return EXIT_CODE;
}
