#ifndef ENCRYPTION
#define ENCRYPTION

#include "key_manager.h"

typedef struct
{
  unsigned char* data;
  size_t size;
} Data;

Data* encrypt_data(Data* plain, KeyManager* KM, int autofree);
Data* decrypt_data(Data* encrypted, KeyManager* KM, int autofree);

Data* DataFromString(char* string, int autofree);
char* DataToString(Data* data, int autofree);
void DataFree(Data* data);
void DataPrint(Data* data);
#endif
