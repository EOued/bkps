#ifndef MACROS
#define MACROS

#include <stdio.h>

#define ERROR(msg)                                                             \
  do                                                                           \
  {                                                                            \
    fprintf(stderr, "%s\n", msg);                                              \
    exit(1);                                                                   \
  } while (0);

#define FREE(ptr)                                                              \
  do                                                                           \
  {                                                                            \
    if (ptr) free(ptr);                                                        \
  } while (0);

#endif
