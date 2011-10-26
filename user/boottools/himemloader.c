#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#ifdef CONFIG_BOOTTOOLS_HIMEMLOADER_EMULATE_CHIP_RESET
#include <linux/config.h>
#ifdef CONFIG_UCSIMM
#include <asm/MC68EZ328.h>
#endif
#ifdef CONFIG_M68VZ328
#include <asm/MC68VZ328.h>
#endif
#endif

#define BUFSIZE 4096
#define HIMEM_LOCATION 0x00600000

char spinner[] = { 8, '|' , 8, '\\' , 8, '-', 8, '/'};

void trap(void) {
  __asm__ __volatile__ ("oriw #0x2700,%sp@; rte;");
};

int main(int argc,char* argv[]) {

  int fd,cnt,i,b=0;
  char *file;
  unsigned char *himem, buf[BUFSIZE];

  if(argc!=2) {
    printf("usage: himemloader <image.bin>\n");
    return 0;
  };

  file=argv[1];

  fd=open(file,O_RDONLY);
  if(fd==-1) {
    printf("error opening file [%s]\n",file);
    return -1;
  };

  printf("Loading file [%s]\n", file);

  himem=(char*)HIMEM_LOCATION;

  while((cnt=read(fd,buf,BUFSIZE))) {
    write(1, &spinner[(b++ & 3) << 1], 2);
    for(i=0;i<cnt;i++) {
      *himem++=buf[i];
    };
  };

  close(fd);

  // switch to supervisor mode
  *((int*)0x000000a8)=(int)trap;
  __asm__ __volatile__ ("trap #10");

#if CONFIG_BOOTTOOLS_HIMEMLOADER_EMULATE_CHIP_RESET
  SCR = 0x1C;
  CSGBA = 0x0000;
  CSGBB = 0x0000;
  CSGBC = 0x0000;
  CSGBD = 0x0000;
  CSA = 0x00E0;
  CSB = 0x0000;
  CSC = 0x0000;
  CSD = 0x0200;
  EMUCS = 0x0060;
  PLLCR = 0x2340;
  PLLFSR = 0x0123;
  PCTRL = 0x1F;
  IVR = 0x00;
  ICR = 0x0000;
  IMR = 0x00FFFFFF;
  ISR = 0x00000000;
  IPR = 0x00000000;
  PADIR = 0x00;
  PADATA = 0x00;
  PAPUEN = 0xFF;
  PBDIR = 0x00;
  PBDATA = 0x00;
  PBPUEN = 0xFF;
  PBSEL = 0xFF;
  PCDIR = 0x00;
  PCDATA = 0x00;
  PCPDEN = 0xFF;
  PCSEL = 0xFF;
  PDDIR = 0x00;
  PDDATA = 0x00;
  PDPUEN = 0xFF;
  PDSEL = 0xF0;
  PDPOL = 0x00;
  PDIRQEN = 0x00;
  PDKBEN = 0x00;
  PDIQEG = 0x00;
  PEDIR = 0x00;
  PEDATA = 0x00;
  PEPUEN = 0xFF;
  PESEL = 0xFF;
  PFDIR = 0x00;
  PFDATA = 0x00;
  PFPUEN = 0xFF;
  PFSEL = 0x00;
  PGDIR = 0x00;
  PGDATA = 0x00;
  PGPUEN = 0x3D;
  PGSEL = 0x08;
  PWMC = 0x0020;
  PWMP = 0xFE;
  PWMCNT = 0x00;
  TCTL = 0x0000;
  TPRER = 0x0000;
  TCMP = 0xFFFF;
  TCR = 0x0000;
  TCN = 0x0000;
  TSTAT = 0x0000;
  SPIMDATA = 0x0000;
  SPIMCONT = 0x0000;
  USTCNT = 0x0000;
  UBAUD = 0x003F;
  URX = 0x0000;
  UTX = 0x0000;
  UMISC = 0x0000;
  NIPR = 0x0000;
  LSSA = 0x00000000;
  LVPW = 0xFF;
  LXMAX = 0x03FF;
  LYMAX = 0x01FF;
  LCXP = 0x0000;
  LCYP = 0x0000;
  LCWCH = 0x0101;
  LBLKC = 0x7F;
  LPICF = 0x00;
  LPOLCF = 0x00;
  LACDRC = 0x00;
  LPXCD = 0x00;
  LCKCON = 0x40;
  LRRA = 0xFF;
  LPOSR = 0x00;
  LFRCM = 0xB9;
  LGPMR = 0x84;
  PWMR = 0x0000;
  RTCTIME = 0x00000000;
  RTCALRM = 0x00000000;
  WATCHDOG = 0x0001;
  RTCCTL = 0x00;
  RTCISR = 0x00;
  RTCIENR = 0x00;
  STPWCH = 0x00;
  DAYALARM = 0x0000;
  // DRAMMC = 0x00000000;
  // DRAMC = 0x00000000;
  ICEMACR = 0x00000000;
  ICEMAMR = 0x00000000;
  ICEMCCR = 0x0000;
  ICEMCMR = 0x0000;
  ICEMCR = 0x0000;
  ICEMSR = 0x0000;
#endif

  // start loaded kernel
  __asm__ __volatile__ ("movel #0x00600004,%a0; jmp (%a0);");

  return 0;
};
