/* make a file with holes */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

char buf[2048];

int
main(int argc, char *argv[])
{
  int count;
  int pos;
  int zcount;
  int b;
  int len;
  int in = open(argv[1], O_RDONLY);
  
  len = lseek(in, 0, SEEK_END);
fprintf(stderr, "TOTAL LEN=%x", len);
  
  lseek(in, 0, SEEK_SET);
  
  len = htonl(len);
  
  write(1, &len, 4);
fprintf(stderr, "[%x]\n", len);

  pos = zcount = count = 0;
  while(read(in, &buf[count], 1) > 0) {
    pos++;
    if (count || buf[count]) {
      count++;
      if (buf[count] == 0) 
        zcount++;
      if ((zcount == 8) || (count == 2048)) {
      	b = htonl(pos-count);
      	write(1,&b,4);
fprintf(stderr, "POS=%x[%x]:", pos-count, b);
      	b = htonl(count);
      	write(1,&b,4);
fprintf(stderr, "LEN=%x[%x]", count, b);
        write(1,buf,count);
fprintf(stderr, "    -->   DATA=%x\n", buf[0]);
	count = zcount = 0;
      }
    }
  }
  if (count) {
    b = htonl(pos-count);
    write(1,&b,4);
fprintf(stderr, "(%d)=%x\n", 4, b);
    b = htonl(count);
    write(1,&b,4);
    write(1,buf,count);
fprintf(stderr, "(%d)=%x    -->   (%d)=%x\n", 4, b, count, buf[0]);
  }
}
