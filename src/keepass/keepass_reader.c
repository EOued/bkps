// References: https://gist.github.com/lgg/e6ccc6e212d18dd2ecd8a8c116fb1e45
// https://gist.github.com/xsleonard/7341172

#include "keepass_reader.h"
#include "macros.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned char* hexstr_to_char(const char* hexstr)
{
  size_t len = strlen(hexstr);
  if (len % 2 != 0) return NULL;
  size_t final_len    = len / 2;
  unsigned char* chrs = (unsigned char*)malloc((final_len + 1) * sizeof(*chrs));
  for (size_t i = 0, j = 0; j < final_len; i += 2, j++)
    chrs[j] = (hexstr[i] % 32 + 9) % 25 * 16 + (hexstr[i + 1] % 32 + 9) % 25;
  chrs[final_len] = '\0';
  return chrs;
}

void free_header(header* header)
{
  if (!header) return;
  FREE(header->seed);
  FREE(header->nonce);
  FREE(header->kdf_parameter)
  FREE(header);
}

header* read_keepass_header(FILE* file);

void read_header(FILE* file)
{
  size_t fs;
  enum file_version fv;
  fread(&fs, 4, 1, file);
  if (fs != FILE_SIGNATURE_VALIDATION) ERROR("Not a keepass file");
  fread(&fv, 4, 1, file);
  header* h;
  switch (fv)
  {
  case KDB: ERROR("Not implemented"); break;
  case PRE_KDBX: ERROR("Not implemented"); break;
  case KDBX: h = read_keepass_header(file); break;
  default: ERROR("Not a valid version");
  }
  free_header(h);
  return;
}

header* read_keepass_header(FILE* file)
{
  enum type type;
  size_t length;
  size_t major_minor_version;
  fread(&major_minor_version, 4, 1, file);
  if (major_minor_version != 0x00040000)
    ERROR("Major/minor version of file not implemented. Supported keepass "
          "version: 4.0");
  unsigned char* content;
  header* h = malloc(sizeof(header));
  if (!h) ERROR("Failed to allocate memory for h");
  h->seed          = NULL;
  h->nonce         = NULL;
  h->kdf_parameter = NULL;

  do
  {
    fread(&type, 1, 1, file);
    fread(&length, 4, 1, file);
    content = malloc(length);
    fread(content, length, 1, file);
    switch (type)
    {
    case CYPHER_ID:
      h->compression_algorithm = UNKNOWN;
      if (!memcmp(content, AES_256_CIPHER, length))
        h->compression_algorithm = AES256;
      if (!memcmp(content, CHACHA20_CIPHER, length))
        h->compression_algorithm = CHACHA20;
      break;
    case COMPRESSIONS_FLAGS:
      memcpy(&h->compression_flag, content, length);
      break;
    case MASTER_SEED:
    case ENCRYPTION_IV:
    case KDF_PARAMETER:
    {
      unsigned char** elem =
          type == MASTER_SEED
              ? &h->seed
              : (type == ENCRYPTION_IV ? &h->nonce : &h->kdf_parameter);
      *elem = malloc(length);
      if (!*elem) ERROR("Failed to allocate memory for seed\n");
      memcpy(*elem, content, length);
      break;
    }
    case END_OF_HEADER:
      if (memcmp(content, EOH, length)) ERROR("Bad value for end of header");
      break;
    default: break;
    }
    free(content);
  } while (type != END_OF_HEADER);

  return h;
}
