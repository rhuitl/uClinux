/* pilrctst.c:  Test program for PilRC
 *
 * Wes Cherry
 * wesc@ricochet.net
 */

#pragma pack(2)

#include "PalmLoader.h"
#include <Common.h>
#include <System/SysAll.h>
#include <UI/UIAll.h>
#include <SerialMgr.h>

int MC(char *dst, char *src, int len) { while (len--) *(dst++) = *(src++); }

int kidForm;

hex(unsigned char * buf)
{
	int i;
	int j;

	for (i=0;i<4;i++) {
		printf("%p",buf);
		for (j=0;j<8; j++) {
			printf(" %.2x",*(buf++)&0xff);
		}
		printf("\n");
	}
}

#if 0

int
DumpPorts ()
{
  printf ("PortA DDR  %.2x\n", *(volatile unsigned char *) 0xfffff400);
  printf ("PortA DATA %.2x\n", *(volatile unsigned char *) 0xfffff401);

  printf ("PortB DDR  %.2x\n", *(volatile unsigned char *) 0xfffff408);
  printf ("PortB DATA %.2x\n", *(volatile unsigned char *) 0xfffff409);

  printf ("PortC DDR  %.2x\n", *(volatile unsigned char *) 0xfffff410);
  printf ("PortC DATA %.2x\n", *(volatile unsigned char *) 0xfffff411);

  printf ("PortD DDR  %.2x\n", *(volatile unsigned char *) 0xfffff418);
  printf ("PortD DATA %.2x\n", *(volatile unsigned char *) 0xfffff419);

  printf ("PortE DDR  %.2x\n", *(volatile unsigned char *) 0xfffff420);
  printf ("PortE DATA %.2x\n", *(volatile unsigned char *) 0xfffff421);

  printf ("PortF DDR  %.2x\n", *(volatile unsigned char *) 0xfffff428);
  printf ("PortF DATA %.2x\n", *(volatile unsigned char *) 0xfffff429);
  printf ("UART Misc %.4x\n", *(volatile unsigned short *) 0xfffff908);
}


int
DumpMapping ()
{
  printf ("FLASH Base %.4x\n", *(volatile unsigned short *) 0xfffff100);
  printf ("FLASH Block %.4x\n", *(volatile unsigned short *) 0xfffff110);

  printf ("DRAM Config %.4x\n", *(volatile unsigned short *) 0xfffffc00);
  printf ("DRAM Contrl %.4x\n", *(volatile unsigned short *) 0xfffffc02);
  printf ("DRAM Base %.4x\n", *(volatile unsigned short *) 0xfffff106);
  printf ("DRAM Block %.4x\n", *(volatile unsigned short *) 0xfffff116);
}

#endif

VoidHand hdl[256];
void *blk[256];
char tmp[4096];

DWord
PilotMain (Word cmd, Ptr cmdPBP, Word launchFlags)
{
  short err;
  EventType e;
  FormType *pfrm;
  int i;
  int j;
  void *ptr;

  if (!cmd)
    {
      kidForm = kidForm1;
      FrmGotoForm (kidForm);

      while (1)
	{
	  EvtGetEvent (&e, 100);
	  if (SysHandleEvent (&e))
	    continue;
	  if (MenuHandleEvent ((void *) 0, &e, &err))
	    continue;

	  switch (e.eType)
	    {
	    case ctlSelectEvent:
	      if (e.data.ctlSelect.controlID == kidOk)
		{
		  printf ("Locking resources...\n");
                  for (i=0; i<256; i++) {
                    hdl[i] = DmGetResource('page', i);
                    if (!hdl[i]) {
		       blk[i] = (void *)0;
		       break;
		    }
                    blk[i] = MemHandleLock(hdl[i]);
                    if (!blk[i]) {
                       printf("\nFailed to lock page %d\n",i);
                       break;
                    }
                  }
		  printf("%d pages in 0x%.6lx bytes\n",i,(long)i*(long)4096);
		  printf("Ordering image pages...\n");
                  asm volatile ("movew #0x069b, 0xfffff116");
                  asm volatile ("movew #0x2700, %sr");

                  ptr = (void *)0;
                  for (i=0; blk[i]; i++) {
		    for (j=i+1; blk[j]; j++) {
                      if (blk[j] < blk[i]) {
                        /* wrong order... swap */
                        MC(tmp, blk[j], 4096);
                        MC(blk[j], blk[i], 4096);
                        MC(blk[i], tmp, 4096);
                        ptr = blk[j];
                        blk[j] = blk[i];
                        blk[i] = ptr;
                      }
                    }
                  }
                  // printf("Done\n");

		  /* Ok!  Ints off, move the boot code to 0x400 and jump */
                  asm volatile ("movew #0x2700, %sr; moveal #0x1ffff0, %ssp");
                  asm volatile ("movew #0x069b, 0xfffff116");
		  MC((void *)0x400, blk[0], 4096);
		  MC((void *)0x000, (void *) blk, 1024);
		  asm volatile ("movel #0, %a0; jmp 0x800");
		}
	      goto Dft;
	      break;
	    case frmLoadEvent:
	      FrmSetActiveForm (FrmInitForm (e.data.frmLoad.formID));
	      break;

	    case frmOpenEvent:
	      pfrm = FrmGetActiveForm ();
	      FrmDrawForm (pfrm);
	      break;

	    case menuEvent:
	      FrmAlert (kidAlert1);
	      break;

	    case appStopEvent:
	      return 0;

	    default:
	    Dft:
	      FrmHandleEvent (FrmGetActiveForm (), &e);
	    }
	}
    }
  return 0;
}
