#ifndef __NEEDS_ESCAPE__
#define __NEEDS_ESCAPE__
unsigned long _needs_escape[8] = {
  0xffffffff, 0x780000fd, 0x78000001, 0xb8000001, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff
 };
#define needs_escape(c) (_needs_escape[(c)>>5]&(1<<((c)&0x1f)))
#endif
