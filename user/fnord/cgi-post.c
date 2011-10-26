#include <stdlib.h>

static void __write1(const char *str)
{
  write(1, str, strlen(str));
}

int main() {
  char* method=getenv("REQUEST_METHOD");
  if (!method) {
    __write1("Content-Type: text/plain\r\n\r\nFatal: $REQUEST_METHOD not set!\n");
    return 1;
  }
  if (!strcmp(method,"GET")) {
    char* c=getenv("QUERY_STRING");
    __write1("Content-Type: text/plain\r\n\r\n");
    if (c)
      write(1,c,strlen(c));
    else {
      __write1("Fatal: $QUERY_STRING not set!\n");
      return 1;
    }
  } else if (!strcmp(method,"POST")) {
    char* c=getenv("CONTENT_TYPE");
    char* d=getenv("CONTENT_LENGTH");
    int l;
    if (!c) {
      __write1("Content-Type: text/plain\r\n\r\nFatal: $CONTENT_TYPE not set!\n");
      return 1;
    }
    if (!d) {
      __write1("Content-Type: text/plain\r\n\r\nFatal: $CONTENT_LENGTH not set!\n");
      return 1;
    }
    {
      char* e;
      l=strtoul(d,&e,10);
      if (e==d || *e) {
	__write1("Content-Type: text/plain\r\n\r\nFatal: $CONTENT_LENGTH not a number: ");
	__write1(d);
	__write1("\n");
	return 1;
      }
    }
    __write1("Content-Type: "); __write1(c); __write1("\r\n");
    __write1("Content-Length: "); __write1(d); __write1("\r\n\r\n");
    while (l>0) {
      char buf[2048];
      int r;
      r=read(0,buf,sizeof(buf));
      if (r==-1) return 1;
      if (r==0) break;
      l-=r;
      write(1,buf,r);
    }
  } else {
    puts("Content-Type: text/plain\r\n\r\nFatal: $REQUEST_METHOD is neither GET nor POST!\n");
  }
}
