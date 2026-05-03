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

void read_keepass_header(FILE* file);

void read_header(FILE* file)
{
  size_t fs;
  enum file_version fv;
  fread(&fs, 4, 1, file);
  if (fs != FILE_SIGNATURE_VALIDATION) ERROR("Not a keepass file");
  fread(&fv, 4, 1, file);
  switch (fv)
  {
  case KDB: ERROR("Not implemented"); break;
  case PRE_KDBX: ERROR("Not implemented"); break;
  case KDBX: read_keepass_header(file); break;
  default: ERROR("Not a valid version");
  }
}

void read_keepass_header(FILE* file)
{
  enum type type;
  size_t length;
  size_t major_minor_version;
  fread(&major_minor_version, 4, 1, file);
  if (major_minor_version != 0x00040000)
    ERROR("Major/minor version of file not implemented. Supported keepass "
          "version: 4.0");
  unsigned char* content;

  do
  {
    fread(&type, 1, 1, file);
    fread(&length, 4, 1, file);
    printf("Type is %u, length is %lu, content is [", type, length);
    content = malloc(length);
    fread(content, length, 1, file);
    for (size_t i = 0; i < length; i++) printf("%x ", content[i]);
    printf("]\n");

    switch (type)
    {
    case 2:
    {
      if (!memcmp(content, AES_256_CIPHER, length))
      {
        printf("\tUse AES-256 Algorithm\n");
        break;
      }
      if (!memcmp(content, CHACHA20_CIPHER, length))
      {
        printf("\tUse ChaCha20 Algorithm\n");
        break;
      }
      printf("Unknown algorithm; If you use a plugin, please not that they are "
             "not supported (yet).");
    }
    default: break;
    }
    free(content);
  } while (type != END_OF_HEADER);
}
