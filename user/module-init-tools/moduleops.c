/* The nasty work of reading 32 and 64-bit modules is in here. */
#include <elf.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "depmod.h"
#include "moduleops.h"
#include "tables.h"

#define PERBIT(x) x##32
#define ElfPERBIT(x) Elf32_##x
#define ELFPERBIT(x) ELF32_##x
#include "moduleops_core.c"

#undef PERBIT
#undef ElfPERBIT
#undef ELFPERBIT
#define PERBIT(x) x##64
#define ElfPERBIT(x) Elf64_##x
#define ELFPERBIT(x) ELF64_##x
#include "moduleops_core.c"
