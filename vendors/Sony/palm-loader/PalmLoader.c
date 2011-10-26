/* pilrctst.c:  Test program for PilRC
 *
 * Wes Cherry
 * wesc@ricochet.net
 */

#pragma pack(2)

#include "PalmLoader.h"
#include <PalmOS.h>
#include <PalmCompatibility.h>

int MC(char *dst, char *src, int len) { while (len--) *(dst++) = *(src++); }

int kidForm;

#define NPAGES 4096

DWord
PilotMain (Word cmd, Ptr cmdPBP, Word launchFlags)
{
  short err;
  EventType e;
  FormType *pfrm;

  int i;
  int j;
  void *ptr;

  VoidHand* hdl;
  void** blk;
  char* tmp;

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
                  hdl = MemPtrNew(sizeof(VoidHand) * NPAGES);
                  blk = MemPtrNew(sizeof(void*) * NPAGES);
                  tmp = MemPtrNew(0x1000);
                  if(!hdl || !blk || !tmp) {
                    printf ("Can't allocate enough memory\n");
                    break;
                  }
		  printf ("Locking resources...\n");
                  for (i=0; i<NPAGES; i++) {
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
		  printf("%d pages in 0x%.6lX bytes\n", i, (long)i * 0x1000);
                  /* supervisor mode, no interrupts */
                  asm volatile ("movew #0x2700, %sr");
                  *((volatile unsigned int*) 0xFFFFF116) &= ~0xE000;
                  /* reorder pages */
                  printf("Ordering image pages...\n");
                  ptr = (void *)0;
                  for (i=0; blk[i]; i++) {
                   for (j=i+1; blk[j]; j++) {
                      if (blk[j] < blk[i]) {
                        /* wrong order... swap */
                        MC(tmp, blk[j], 0x1000);
                        MC(blk[j], blk[i], 0x1000);
                        MC(blk[i], tmp, 0x1000);
                        ptr = blk[j];
                        blk[j] = blk[i];
                        blk[i] = ptr;
                      }
                    }
                  }
                  /* kernel starts at 0x4000, entry point at 0x4400 */
		  MC((void*) 0x0000, (void *) blk, sizeof(void*) * NPAGES);
		  MC((void*) 0x4000, (void*)(*(unsigned long*)0), 0x1000);
                  asm volatile ("moveal #0xFFFFF0, %sp");
		  asm volatile ("movel #0, %a0");
                  asm volatile ("jmp 0x4400");
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
