/*
 * $Id: crc32.c,v 1.1.1.1 2002/03/28 00:02:10 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * This file contains CRC32 calculation routines.
 *
 */

#include "arj.h"

DEBUGHDR(__FILE__)                      /* Debug information block */

#define CRCPOLY          0xEDB88320L    /* CRC32 polynomial */
#define UPDATE_CRC(r, c) crc32tab[((unsigned char)(r)^(unsigned char)(c))&0xFF]^(r>>CHAR_BIT)

unsigned long crc32term;
#ifdef ASM8086
 unsigned short crc32tab_lo[256];
 unsigned short crc32tab_hi[256];
 static unsigned short xbp;
#else
 unsigned long crc32tab[256];
#endif

/* CRC32 initialization */

void build_crc32_table()
{
 #ifdef ASM8086
  asm{
                push    si
                push    di
                xor     di, di
                jmp     short lt_0
  }
loop_ch:
  asm{
                mov     dx, di
                xor     ax, ax
                mov     si, 8
                or      si, si
                jmp     short lt_1
  }
loop_term:
  asm{
                test    dx, 1
                jz      lt_next
                shr     ax, 1
                rcr     dx, 1
                xor     dx, 8320h
                xor     ax, 0EDB8h
                jmp     short lt_next_c
  }
lt_next:
  asm{
                shr     ax, 1
                rcr     dx, 1
  }
lt_next_c:
  asm{
                dec     si
  }
lt_1:
  asm{
                jg      loop_term
                mov     bx, di
                shl     bx, 1
                mov     word ptr crc32tab_lo[bx], dx
                mov     word ptr crc32tab_hi[bx], ax
                inc     di
  }
lt_0:
  asm{
                cmp     di, 0FFh
                jbe     loop_ch
                pop     di
                pop     si
  }
 #else
  unsigned int i, j;
  unsigned long r;

  for(i=0; i<=UCHAR_MAX; i++)
  {
   r=i;
   for(j=CHAR_BIT; j>0; j--)
   {
    if(r&1)
     r=(r>>1)^CRCPOLY;
    else
     r>>=1;
   }
   crc32tab[i]=r;
  }
 #endif
}

/* Calculates CRC32 for a given block */

void crc32_for_block(char *block, unsigned int b_size)
{
 #ifdef ASM8086
  asm{
                push    si
                push    di
                cld
                mov     word ptr xbp, bp
                mov     bx, offset crc32tab_lo
                mov     cl, 4
                shr     bx, cl
                mov     cx, word ptr crc32term[0]
                mov     dx, word ptr crc32term[2]
                mov     si, block
                mov     di, b_size
                push    ds
                mov     ax, ds
                mov     es, ax
                add     ax, bx
                xor     bx, bx
                mov     bp, di
                and     di, 3
                push    di
                shr     bp, 1
                shr     bp, 1
                jz      lt_shloop
  }
lt_accterm:
#if COMPILER==BCC
  asm{
		db	26h, 0ADh
  }
#else
  asm{
                lods    word ptr es:[si]
  }
#endif
  asm{
                mov     bl, cl
                xor     bl, al
                mov     cl, ch
                mov     ch, dl
                mov     dl, dh
                mov     dh, bh
                mov     di, bx
                shl     di, 1
                xor     cx, crc32tab_lo[di]
                xor     dx, crc32tab_hi[di]
                mov     bl, cl
                xor     bl, ah
                mov     cl, ch
                mov     ch, dl
                mov     dl, dh
                mov     dh, bh
                mov     di, bx
                shl     di, 1
                xor     cx, crc32tab_lo[di]
                xor     dx, crc32tab_hi[di]
  }
#if COMPILER==BCC
  asm{
		db	26h, 0ADh
  }
#else
  asm{
                lods    word ptr es:[si]
  }
#endif
  asm{
                mov     bl, cl
                xor     bl, al
                mov     cl, ch
                mov     ch, dl
                mov     dl, dh
                mov     dh, bh
                mov     di, bx
                shl     di, 1
                xor     cx, crc32tab_lo[di]
                xor     dx, crc32tab_hi[di]
                mov     bl, cl
                xor     bl, ah
                mov     cl, ch
                mov     ch, dl
                mov     dl, dh
                mov     dh, bh
                mov     di, bx
                shl     di, 1
                xor     cx, crc32tab_lo[di]
                xor     dx, crc32tab_hi[di]
                dec     bp
                jnz     lt_accterm
  }
lt_shloop:
  asm{
                pop     bp
                or      bp, bp
                jz      lt_exit
  }
lt_shift:
#if COMPILER==BCC
  asm{
		db	26h, 0ACh
  }
#else
  asm{
                lods    byte ptr es:[si]
  }
#endif
  asm{
                mov     bl, cl
                xor     bl, al
                mov     cl, ch
                mov     ch, dl
                mov     dl, dh
                mov     dh, bh
                mov     di, bx
                shl     di, 1
                xor     cx, crc32tab_lo[di]
                xor     dx, crc32tab_hi[di]
                dec     bp
                jnz     lt_shift
  }
lt_exit:
  asm{
                pop     ds
                mov     word ptr crc32term[0], cx
                mov     word ptr crc32term[2], dx
                pop     di
                pop     si
                mov     bp, word ptr xbp
  }
 #else
  while(b_size--)
   crc32term=UPDATE_CRC(crc32term, *block++);
 #endif
}

#if SFX_LEVEL>=ARJSFX||defined(REARJ)||defined(REGISTER)||defined(ARJUTIL)

/* Calculates CRC32 for a given ASCIIz string */

void crc32_for_string(char *sptr)
{
 #ifdef ASM8086
  asm{
                push    si
                push    di
                cld
                xor     bx, bx
                mov     si, sptr
                mov     cx, word ptr crc32term[0]
                mov     dx, word ptr crc32term[2]
                jmp     short str_nchar
  }
stracc:
  asm{
                mov     bl, cl
                xor     bl, al
                mov     cl, ch
                mov     ch, dl
                mov     dl, dh
                mov     dh, bh
                mov     di, bx
                shl     di, 1
                xor     cx, word ptr crc32tab_lo[di]
                xor     dx, word ptr crc32tab_hi[di]
  }
str_nchar:
  asm{
                lodsb
                or      al, al
                jnz     stracc
                mov     word ptr crc32term[0], cx
                mov     word ptr crc32term[2], dx
                pop     di
                pop     si
  }
 #else
  while(*sptr!='\0')
   crc32term=UPDATE_CRC(crc32term, (unsigned char)(*sptr++));
 #endif
}

/* Evaluates CRC32 based on character and term given */

unsigned long crc32_for_char(unsigned long crc32_term, unsigned char newc)
{
 #ifdef ASM8086
  asm{
                mov     ax, word ptr crc32_term
                mov     dx, word ptr crc32_term+2
                mov     bl, al
                mov     al, ah
                mov     ah, dl
                mov     dl, dh
                mov     dh, 0
                xor     bl, newc
                mov     bh, 0
                shl     bx, 1
                xor     ax, word ptr crc32tab_lo[bx]
                xor     dx, word ptr crc32tab_hi[bx]
  }
 #else
  return(UPDATE_CRC(crc32_term, newc));
 #endif
}

#endif

