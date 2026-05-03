#include "encryption.h"
#include "keepass_reader.h"
#include "key_manager.h"
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
  FILE* f = fopen("test.kdbx", "r");
  read_header(f);
  fclose(f);
}
