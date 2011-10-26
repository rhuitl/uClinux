#include <stdio.h>

main() {
  printf("Content-Type: text/plain\r\n\r\n%d %d\n",getuid(),geteuid());
  setuid(0); seteuid(0);
  printf("%d %d\n",getuid(),geteuid());
}
