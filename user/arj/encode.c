/*
 * $Id: encode.c,v 1.7 2004/05/31 16:08:41 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * The data compression procedures are located in this module.
 *
 */

#include "arj.h"

#ifdef TILED
 #include <dos.h>                       /* Weird, eh? */
#endif

DEBUGHDR(__FILE__)                      /* Debug information block */

static int st_n;

unsigned short *c_freq;
unsigned short FAR *c_code;
unsigned short FAR *heap;
unsigned short len_cnt[17];
unsigned short p_freq[2*NP-1];
unsigned short pt_code[NPT];
int depth;
unsigned char FAR *buf;
unsigned char output_mask;
unsigned short output_pos;
int dicbit;
unsigned short t_freq[2*NT-1];
int heapsize;
unsigned short FAR *sortptr;
unsigned char *len;
unsigned short *freq;
unsigned short fpcount;
short FAR *fpbuf;
short FAR *dtree;
unsigned short treesize;
unsigned char *tree=NULL;
unsigned short numchars;
unsigned short dicsiz_cur;
unsigned short dicpos;
unsigned short tc_passes;
short FAR *ftree;
unsigned int dic_alloc;
unsigned long encoded_bytes;

/* Inline functions */

#define encode_c(c)                     \
        putbits(c_len[c], c_code[c])

#define encode_p(p)                     \
{                                       \
 unsigned int qc, q;                    \
 qc=0;                                  \
 q=p;                                   \
 while(q)                               \
 {                                      \
  q>>=1;                                \
  qc++;                                 \
 }                                      \
 putbits(pt_len[qc], pt_code[qc]);      \
 if(qc>1)                               \
  putbits(qc-1, p);                     \
}

/* Bitwise output routine */

void putbits(int n_c, unsigned short n_x)
{
 #ifdef ASM8086
  asm{
                mov     cl, byte ptr n_c
                mov     dx, n_x
                mov     ch, cl
                sub     cl, 16
                neg     cl
                shl     dx, cl
                mov     cl, byte ptr bitcount
                mov     ax, dx
                shr     ax, cl
                or      bitbuf, ax
                add     cl, ch
                cmp     cl, 8
                jge     chunk1
                mov     byte ptr bitcount, cl
                jmp     procend
  }
chunk1:
  asm{
                push    si
                mov     si, out_bytes
                cmp     si, out_avail
                jge     flush
  }
acc_loop:
  asm{
                mov     bx, out_buffer
                mov     ah, byte ptr bitbuf+1
                mov     [bx+si], ah
                inc     si
                sub     cl, 8
                cmp     cl, 8
                jge     avail_chk
 #if TARGET==OS2
                shl     bitbuf, 8
 #else
                mov     ah, byte ptr bitbuf
                mov     al, 0
                mov     bitbuf, ax
 #endif
                jmp     endpoint
  }
avail_chk:
  asm{
                cmp     si, out_avail
                jge     r_flush
  }
cpoint:
  asm{
                mov     al, byte ptr bitbuf
                mov     [bx+si], al
                inc     si
                sub     cl, 8
                sub     ch, cl
                xchg    cl, ch
                shl     dx, cl
                mov     bitbuf, dx
                mov     cl, ch
                jmp     endpoint
  }
flush:
  asm{
                push    dx
                push    cx
  }
                flush_compdata();
  asm{
                pop     cx
                pop     dx
                mov     si, out_bytes
                jmp     short acc_loop
  }
 r_flush:
  asm{
                mov     out_bytes, si
                push    dx
                push    cx
                push    bx
  }
                flush_compdata();
  asm{
                pop     bx
                pop     cx
                pop     dx
                mov     si, out_bytes
                jmp     short cpoint
  }
 endpoint:
  asm{
                mov     out_bytes, si
                pop     si
                mov     byte ptr bitcount, cl
  }
 procend:;
 #else
  int p_n;
  int bt;

  p_n=n_c;
  n_c=16-n_c;
  n_x<<=n_c;
  n_c=bitcount;
  bitbuf|=(n_x>>n_c);
  n_c+=p_n;
  if(n_c<8)
  {
   bitcount=n_c;
   return;
  }
  bt=out_bytes;
  if(bt>=out_avail)
  {
   flush_compdata();
   bt=out_bytes;
  }
  out_buffer[bt++]=bitbuf>>8;
  n_c-=8;
  if(n_c<8)
  {
   bitbuf<<=8;
   out_bytes=bt;
   bitcount=n_c;
   return;
  }
  if(bt>=out_avail)
  {
   out_bytes=bt;
   flush_compdata();
   bt=out_bytes;
  }
  out_buffer[bt++]=bitbuf;
  n_c-=8;
  p_n-=n_c;
  bitbuf=n_x<<p_n;
  out_bytes=bt;
  bitcount=n_c;
 #endif
}

/* Quick fill routine */

static void fill_fpbuf()
{
 #ifdef ASM8086
  asm{
                push    di
                cld
                mov     ax, 65535
                les     di, fpbuf
                mov     cx, fpcount
                rep     stosw
                pop     di
  }
 #else
  unsigned int i;

  for(i=0; i<fpcount; i++)
   fpbuf[i]=-1;
 #endif
}

/* Reduces the number of bits for smaller files */

void adjust_dicbit()
{
 if(uncompsize<16384)
  dicbit=12;
}

/* Reads data from the source file or a memory region */

#if SFX_LEVEL>=ARJ
int fetch_uncomp(char *dest, int n)
{
 unsigned int fetch_size;

 if(file_packing)
  return(fread_crc(dest, n, encstream));
 else
 {
  if(encmem_remain==0)
   return(0);
  fetch_size=min((unsigned int)n, encmem_remain);
  far_memmove((char FAR *)dest, encblock_ptr, fetch_size);
  crc32_for_block(dest, fetch_size);
  encmem_remain-=fetch_size;
  encblock_ptr+=fetch_size;
  return(fetch_size);
 }
}
#endif

/* Fills the length table depending on the leaf depth (call with i==root) */

static void count_len(int i)
{
 static int depth=0;

 if(i<st_n)
  len_cnt[(depth<16)?depth:16]++;
 else
 {
  depth++;
  count_len(left[i]);
  count_len(right[i]);
  depth--;
 }
}

/* Makes length counter table */

static void NEAR make_len(int root)
{
 int i, k;
 unsigned short cum;

 for(i=0; i<=16; i++)
  len_cnt[i]=0;
 count_len(root);
 cum=0;
 for(i=16; i>0; i--)
  cum+=len_cnt[i]<<(16-i);
 while(cum!=0)
 {
  if(debug_enabled&&strchr(debug_opt, 'f')!=NULL)
   msg_cprintf(0, M_HDF_FIX);
  len_cnt[16]--;
  for(i=15; i>0; i--)
  {
   if(len_cnt[i]!=0)
   {
    len_cnt[i]--;
    len_cnt[i+1]+=2;
    break;
   }
  }
  cum--;
 }
 for(i=16; i>0; i--)
 {
  k=len_cnt[i];
  while(--k>=0)
   len[*sortptr++]=i;
 }
}

/* Sends i-th entry down the heap */

static void NEAR downheap(int i)
{
 int j, k;

 k=heap[i];
 while((j=2*i)<=heapsize)
 {
  if(j<heapsize&&freq[heap[j]]>freq[heap[j+1]])
   j++;
  if(freq[k]<=freq[heap[j]])
   break;
  heap[i]=heap[j];
  i=j;
 }
 heap[i]=k;
}

/* Encodes a length table element */

static void NEAR make_code(int n, unsigned char *len, unsigned short FAR *code)
{
 int i;
 unsigned short start[18];

 start[1]=0;
 for(i=1; i<=16; i++)
  start[i+1]=(start[i]+len_cnt[i])<<1;
 for(i=0; i<n; i++)
  code[i]=start[len[i]]++;
}

/* Makes tree, calculates len[], returns root */

static int make_tree(int nparm, unsigned short *freqparm, unsigned char *lenparm, unsigned short FAR *codeparm)
{
 int i, j, k, avail;

 st_n=nparm;
 freq=freqparm;
 len=lenparm;
 avail=st_n;
 heapsize=0;
 heap[1]=0;
 for(i=0; i<st_n; i++)
 {
  len[i]=0;
  if(freq[i]!=0)
   heap[++heapsize]=i;
 }
 if(heapsize<2)
 {
  codeparm[heap[1]]=0;
  return(heap[1]);
 }
 for(i=heapsize>>1; i>=1; i--)
  downheap(i);                          /* Make priority queue */
 sortptr=codeparm;
 /* While queue has at least two entries */
 do
 {
  i=heap[1];                     	/* Take out least-freq entry */
  if(i<st_n)
   *(sortptr++)=i;
  heap[1]=heap[heapsize--];
  downheap(1);
  j=heap[1];                            /* Next least-freq entry */
  if(j<st_n)
   *(sortptr++)=j;
  k=avail++;                     	/* Generate new node */
  freq[k]=freq[i]+freq[j];
  heap[1]=k;
  downheap(1);                   	/* Put into queue */
  left[k]=i;
  right[k]=j;
 } while(heapsize>1);
 sortptr=codeparm;
 make_len(k);
 make_code(nparm, lenparm, codeparm);
 return(k);                            /* Return root */
}

/* Counts the cumulative frequency */

void count_t_freq()
{
 int i, k, n, count;

 for(i=0; i<NT; i++)
  t_freq[i]=0;
 n=NC;
 while(n>0&&c_len[n-1]==0)
  n--;
 i=0;
 while(i<n)
 {
  k=c_len[i++];
  if(k==0)
  {
   count=1;
   while(i<n&&c_len[i]==0)
   {
    i++;
    count++;
   }
   if(count<=2)
    t_freq[0]+=count;
   else if(count<=18)
    t_freq[1]++;
   else if(count==19)
   {
    t_freq[0]++;
    t_freq[1]++;
   }
   else
    t_freq[2]++;
  }
  else
   t_freq[k+2]++;
 }
}

/* Writes the encoded length */

void write_pt_len(int n, int nbit, int i_special)
{
 int i, k;

 while(n>0&&pt_len[n-1]==0)
  n--;
 putbits(nbit, n);
 i=0;
 while(i<n)
 {
  k=(int)pt_len[i++];
  if(k<=6)
  {
   putbits(3, k);
  }
  else
   putbits(k-3, 0xFFFE);
  if(i==i_special)
  {
   while(i<6&&pt_len[i]==0)
    i++;
   putbits(2, i-3);
  }
 }
}

/* Writes character length */

void write_c_len()
{
 int i, k, n, count;

 n=NC;
 while(n>0&&c_len[n-1]==0)
  n--;
 putbits(CBIT, n);
 i=0;
 while(i<n)
 {
  k=(int)c_len[i++];
  if(k==0)
  {
   count=1;
   while(i<n&&c_len[i]==0)
   {
    i++;
    count++;
   }
   if(count<=2)
   {
    for(k=0; k<count; k++)
     putbits(pt_len[0], pt_code[0]);
   }
   else if(count<=18)
   {
    putbits(pt_len[1], pt_code[1]);
    putbits(4, count-3);
   }
   else if(count==19)
   {
    putbits(pt_len[0], pt_code[0]);
    putbits(pt_len[1], pt_code[1]);
    putbits(4, 15);
   }
   else
   {
    putbits(pt_len[2], pt_code[2]);
    putbits(CBIT, count-20);
   }
  }
  else
   putbits(pt_len[k+2], pt_code[k+2]);
 }
}

/* Encodes a block and writes it to the output file */

void send_block()
{
 unsigned int i, k, flags=0, root, pos, size;
 unsigned int c;

 if(!unpackable)
 {
  root=make_tree(NC, c_freq, c_len, c_code);
  size=c_freq[root];
  putbits(16, size);
  if(root>=NC)
  {
   count_t_freq();
   root=make_tree(NT, t_freq, pt_len, (unsigned short FAR *)pt_code);
   if(root>=NT)
    write_pt_len(NT, TBIT, 3);
   else
   {
    putbits(TBIT, 0);
    putbits(TBIT, root);
   }
   write_c_len();
  }
  else
  {
   putbits(TBIT, 0);
   putbits(TBIT, 0);
   putbits(CBIT, 0);
   putbits(CBIT, root);
  }
  root=make_tree(NP, p_freq, pt_len, (unsigned short FAR *)pt_code);
  if(root>=NP)
   write_pt_len(NP, PBIT, -1);
  else
  {
   putbits(PBIT, 0);
   putbits(PBIT, root);
  }
  pos=0;
  for(i=0; i<size; i++)
  {
   if(unpackable)
    return;
   if(i%CHAR_BIT==0)
    flags=buf[pos++];
   else
    flags<<=1;
   if(flags&(1U<<(CHAR_BIT-1)))
   {
    c=(unsigned int)buf[pos++]+(1<<CHAR_BIT);
    encode_c(c);
    k=buf[pos++];
    k|=(unsigned int)buf[pos++]<<CHAR_BIT;
    encode_p(k);
   }
   else
   {
    c=buf[pos++];
    encode_c(c);
   }
  }
  for(i=0; i<NC; i++)
   c_freq[i]=0;
  for(i=0; i<NP; i++)
   p_freq[i]=0;
 }
}

/* Handy macro for retrieval of two bytes (don't care about the portability) */

#ifdef ALIGN_POINTERS
 #define word_ptr(c) (  (((unsigned char *) (c))[0]<<8)+ ((unsigned char *) (c))[1] )
 #define _diff(c1,c2) ( (c1)[0]!=(c2)[0] || (c1)[1]!=(c2)[1] )
#elif !defined(TILED)
 #define word_ptr(c) (*(unsigned short *)(c))
#endif

/* Tree update routine. Possibly the most time-consuming one. */

static int upd_tree(int n_c)
{
 #ifdef ASM8086
  asm{
                push    bp
                push    si
                push    di
                mov     si, n_c
                mov     bp, 1
                mov     es, word ptr dtree+2
                mov     bx, si
                mov     bx, es:[bx+si]
                or      bx, bx
                jl      done_dup
  }
ok:
  asm{
                mov     di, tree
                add     si, di
                add     di, bx
                mov     ax, [si]
                cld
                mov     dx, numchars
                dec     dx
                jge     ut_loop
  }
done_dup:
  asm{
                jmp     done
  }
ut_fetch:
  asm{
                mov     ax, [bp+si-1]
  }
select_pos:
  asm{
                mov     di, tree
                add     di, bp
  }
ut_loopbody:
  asm{
                dec     dx
                jl      ut_brk
                shl     bx, 1
                mov     bx, es:[bx]
                or      bx, bx
                jl      ut_brk
                cmp     ax, [bx+di-1]
                jz      ut_rcount
                dec     dx
                shl     bx, 1
                mov     bx, es:[bx]
                or      bx, bx
                jl      ut_brk
                cmp     ax, [bx+di-1]
                je      ut_rcount
                dec     dx
                shl     bx, 1
                mov     bx, es:[bx]
                or      bx, bx
                jl      ut_brk
                cmp     ax, [bx+di-1]
                je      ut_rcount
                dec     dx
                shl     bx, 1
                mov     bx, es:[bx]
                or      bx, bx
                jl      ut_brk
                cmp     ax, [bx+di-1]
                je      ut_rcount
                dec     dx
                shl     bx, 1
                mov     bx, es:[bx]
                or      bx, bx
                jl      ut_brk
                cmp     ax, [bx+di-1]
                je      ut_rcount
                dec     dx
                shl     bx, 1
                mov     bx, es:[bx]
                or      bx, bx
                jl      ut_brk
                cmp     ax, [bx+di-1]
                je      ut_rcount
                jmp     short ut_loopbody
  }
ut_brk:
  asm{
                jmp     short upd_finish
  }
ut_rcount:
  asm{
                sub     di, bp
                add     di, bx
  }
ut_loop:
  asm{
                mov     cx, [si]
                cmp     cx, [di]
                jnz     select_pos
                mov     ax, ds
                mov     es, ax
                mov     ax, di
                add     di, 2
                add     si, 2
                mov     cx, 128
                repe cmpsw
                mov     cl, [di-2]
                sub     cl, [si-2]
                xchg    ax, di
                sub     ax, di
                sub     si, ax
                sub     cl, 1
                adc     ax, -2
                mov     es, word ptr dtree+2
                cmp     ax, bp
                jg      verify_pos
                jmp     ut_fetch
  }
verify_pos:
  asm{
                mov     cx, si
                sub     cx, di
                cmp     cx, dicsiz_cur
                jg      upd_finish
                dec     cx
                mov     dicpos, cx
                mov     bp, ax
                cmp     bp, 256
                jge     upd_finish
                jmp     ut_fetch
  }
upd_finish:
  asm{
                cmp     bp, 256
                jle     done
                mov     bp, 256
  }
done:
  asm{
                mov     ax, bp
                mov     tc_passes, ax
                pop     di
                pop     si
                pop     bp
  }
  return(tc_passes);
 #else
 short FAR *dptr;
 short r_bx, r_dx;
 unsigned short r_ax;
 short r_bp=1;
 unsigned char *tptr;
 unsigned char *tdptr;
 unsigned char *prev_tptr, *prev_tdptr;
 int c;
 char diff;
 int remainder;

 dptr=dtree;
 if((r_bx=dptr[n_c])>=0)
 {
  tptr=tree+n_c;
  tdptr=tree+r_bx;
  r_ax=word_ptr(tptr);
  r_dx=numchars;
  if(--r_dx>=0)
   goto ut_loop;
ut_fetch:
  r_ax=word_ptr(tptr+r_bp-1);
select_pos:
  tdptr=tree+r_bp;
  do
  {
   if(--r_dx<0)
    goto upd_finish;
   r_bx=dptr[r_bx];
   if(r_bx<0)
    goto upd_finish;
  } while(r_ax!=word_ptr(tdptr+r_bx-1));
  tdptr+=r_bx-r_bp;
ut_loop:
  #ifdef ALIGN_POINTERS
  if (_diff(tptr,tdptr))
  #else  
  if(word_ptr(tptr)!=word_ptr(tdptr))
  #endif
   goto select_pos;
  prev_tptr=tptr;
  prev_tdptr=tdptr;
  tptr+=2;
  tdptr+=2;
  for(c=128; c>0; c--)
  {
   #ifdef ALIGN_POINTERS
   if (_diff(tptr,tdptr))
   #else  
   if(word_ptr(tptr)!=word_ptr(tdptr))
   #endif
    break;
   tptr+=2;
   tdptr+=2;
  }
  diff=*(tdptr)-*(tptr);
  remainder=tdptr-prev_tdptr;
  if(diff==0)
   remainder+=1;
  tptr=prev_tptr;
  tdptr=prev_tdptr;
  if(remainder<=r_bp)
   goto ut_fetch;
  if(tptr-tdptr<=dicsiz_cur)
  {
   dicpos=tptr-tdptr-1;
   r_bp=remainder;
   if(r_bp<256)
    goto ut_fetch;
  }
upd_finish:
  if(r_bp>256)
   r_bp=256;
 }
 return(tc_passes=r_bp);
 #endif
}

/* Optimized output routine */

static void output(int c, unsigned short p)
{
 unsigned char FAR *bptr;
 unsigned char cy;
 unsigned short r_dx;
 unsigned short r_bx;

 bptr=buf;
 r_dx=cpos;
 cy=output_mask&1;
 output_mask=(cy?0x80:0)|((output_mask&0xFF)>>1);
 if(cy)
 {
  if(r_dx>=bufsiz)
  {
   send_block();
   if(unpackable)
   {
    cpos=bptr-buf;
    return;
   }
   r_dx=0;
  }
  output_pos=r_dx;
  buf[r_dx]=0;
  r_dx++;
 }
 bptr+=r_dx;
 *bptr++=c;
 c_freq[c]++;
 if(c>=256)
 {
  buf[output_pos]|=output_mask;
  *bptr++=p&0xFF;
  *bptr++=(p>>8);
  for(r_bx=0; p!=0; p>>=1)
   r_bx++;
  p_freq[r_bx]++;
 }
 cpos=bptr-buf;
}

/* Unstubbed optimized output routine */

static void output_opt(unsigned char c)
{
 unsigned char FAR *bptr, FAR *cptr;
 unsigned short r_dx;
 unsigned char cy;

 cptr=bptr=buf;
 r_dx=cpos;
 cy=output_mask&1;
 output_mask=(cy?0x80:0)|((output_mask&0xFF)>>1);
 if(cy)
 {
  if(r_dx>=bufsiz)
  {
   send_block();
   r_dx=0;
   if(unpackable)
   {
    cpos=r_dx;
    return;
   }
  }
  output_pos=r_dx;
  cptr[r_dx]=0;
  r_dx++;
 }
 bptr+=r_dx;
 *bptr++=c;
 c_freq[c]++;
 cpos=bptr-cptr;
}

/* Initializes memory for encoding */

void allocate_memory()
{
 int i;

 if((c_freq=calloc(NC*2-1, sizeof(*c_freq)))==NULL)
  error(M_OUT_OF_NEAR_MEMORY);
 if((c_code=farcalloc(NC, sizeof(*c_code)))==NULL)
  error(M_OUT_OF_MEMORY);
 if((heap=farcalloc(NC+1, sizeof(*heap)))==NULL)
  error(M_OUT_OF_MEMORY);
 for(i=0; i<NP; i++)
  p_freq[i]=0;
 depth=0;
 bufsiz=current_bufsiz;
 if(bufsiz>=MAX_BUFSIZ-BUFSIZ_INCREMENT)
  bufsiz=MAX_BUFSIZ-1;
 #ifdef FINETUNE_BUFSIZ
  i=1;
 #endif
 /* Adjust the buffer size if there's not enough memory for it */
 while((buf=farmalloc(bufsiz))==NULL)
 {
  #ifndef FINETUNE_BUFSIZ
   bufsiz=bufsiz/10U*9U;
  #else
   if(i<2048)
    bufsiz-=i++;
   else
    bufsiz=bufsiz/16U*15U;
  #endif
  if(bufsiz<MIN_BUFSIZ)
   error(M_OUT_OF_MEMORY);
 }
 if(debug_enabled&&strchr(debug_opt, 'v')!=NULL)
  msg_cprintf(0, M_BUFSIZ, bufsiz);
 init_putbits();
 output_mask=1;
 output_pos=0;
 cpos=0;
 buf[output_pos]='\0';
 bufsiz-=30;
}

/* Shutdown the encoding */

void NEAR huf_encode_end()
{
 if(!unpackable)
  send_block();
 shutdown_putbits();
 free(c_freq);
 farfree(c_code);
 farfree(heap);
 farfree(buf);
 bufsiz=0;
 cpos=0;
}

/* Basic encoding routine */

static void NEAR huf_encode()
{
 int hash_bits;
 unsigned short fp_max;
 int nchars;
 int i, j, m=0;
 short k, l;
 unsigned short t;                      /* Exchange variable */
 int tree_el;
 unsigned int n_passes;
 unsigned int f_dicpos;
 unsigned int fetch;
 unsigned int max_fetch;                /* For comparison */
 short FAR *fptr;
 short FAR *dtptr;
 unsigned char *tptr;
 unsigned short r_cx, r_dx, r_ax;
 int pm;

 hash_bits=(dicbit+2)/3;
 fpcount=1U<<dicbit;
 fp_max=fpcount-1;
 if(tree==NULL)
 {
  if((tree=calloc(treesize+2, sizeof(*tree)))==NULL)
   error(M_OUT_OF_NEAR_MEMORY);
  #ifdef ASM8086
   ftree=farcalloc_based((unsigned long)treesize+16L, sizeof(*ftree));
   dtree=(FP_OFF(ftree)==0)?ftree:MK_FP(FP_SEG(ftree)+((FP_OFF(ftree)+15)>>4), 0);
  #else
   ftree=dtree=farcalloc((unsigned long)treesize+16L, sizeof(*ftree));
  #endif
  fpbuf=farcalloc((unsigned long)fpcount+4L, 2L);
  if(ftree==NULL||fpbuf==NULL)
   error(M_OUT_OF_MEMORY);
 }
 if(dic_alloc<1024)
  dic_alloc=1024;
 allocate_memory();
 nchars=(UCHAR_MAX+THRESHOLD)*2;
 display_indicator(0L);
 encoded_bytes=0L;
 tc_passes=0;
 dicpos=0;
 i=j=0;
 while(!unpackable)
 {
  tree_el=0;
  k=0;
  if(j!=0)
  {
   tree_el=dic_alloc;
   if((k=j-tree_el)<=0)
   {
    k=0;
    tree_el=j;
   }
   else
    memmove(tree, tree+k, tree_el);
  }
  max_fetch=fetch=(unsigned int)(treesize-tree_el);
  if(multivolume_option)
   fetch=check_multivolume(fetch);
  if(max_fetch!=fetch)
   nchars=4;
  if((fetch=fetch_uncomp(tree+tree_el, fetch))==0)
  {
   if(tree_el==0||k==0)
    break;
   memmove(tree+k, tree, tree_el);
   dicsiz_cur=min(tree_el-i-1, dicsiz_cur);
   break;
  }
  j=fetch+tree_el;
  encoded_bytes+=(unsigned long)fetch;
  display_indicator(encoded_bytes);
  m=0;
  if(k<=0)
   fill_fpbuf();
  else
  {
   fptr=fpbuf;
   for(l=fpcount>>2; l>0; l--)
   {
    *fptr=max(*fptr-k, -1);
    fptr++;
    *fptr=max(*fptr-k, -1);
    fptr++;
    *fptr=max(*fptr-k, -1);
    fptr++;
    *fptr=max(*fptr-k, -1);
    fptr++;
   }
   dtptr=dtree;
   for(l=tree_el>>3; l>0; l--)
   {
    *dtptr=max(dtptr[k]-k, -1);
    dtptr++;
    *dtptr=max(dtptr[k]-k, -1);
    dtptr++;
    *dtptr=max(dtptr[k]-k, -1);
    dtptr++;
    *dtptr=max(dtptr[k]-k, -1);
    dtptr++;
    *dtptr=max(dtptr[k]-k, -1);
    dtptr++;
    *dtptr=max(dtptr[k]-k, -1);
    dtptr++;
    *dtptr=max(dtptr[k]-k, -1);
    dtptr++;
    *dtptr=max(dtptr[k]-k, -1);
    dtptr++;
   }
   /* Store the remainder */
   for(l=tree_el%8; l>0; l--)
   {
    *dtptr=max(dtptr[k]-k, -1);
    dtptr++;
   }
   m+=tree_el;
   if(m>=2)
    m-=2;
  }
  tptr=&tree[m];
  r_dx=(unsigned short)*(tptr++);
  r_cx=(fp_max&0xFF00)|(hash_bits&0xFF);
  r_dx<<=(hash_bits&0xFF);
  r_dx^=(unsigned short)*(tptr++);
  r_dx&=(r_cx|0xFF);
  for(l=j-2; m<l; m++)
  {
   r_dx<<=(r_cx&0xFF);
   r_dx^=*(tptr++);
   r_dx&=(r_cx|0xFF);
   t=fpbuf[r_dx];
   fpbuf[r_dx]=m;
   dtree[m]=t;
  }
  dtree[m]=-1;
  dtree[m+1]=-1;
  m=tree_el-i;
  i+=fetch;
  while(i>nchars)
  {
   i--;
   pm=m;
   m++;
   n_passes=(unsigned int)tc_passes;
   f_dicpos=(int)dicpos;
   if((r_ax=upd_tree(m))>i)
    r_ax=tc_passes=i;
   if(n_passes<THRESHOLD||(n_passes==THRESHOLD&&f_dicpos>16384)||--r_ax>n_passes||(r_ax==n_passes&&dicpos>>1<f_dicpos))
   {
    output_opt(tree[pm]);
   }
   else
   {
    i-=n_passes-1;
    m+=n_passes-1;
    r_ax=n_passes+UCHAR_MAX-2;
    output(r_ax, f_dicpos);
    upd_tree(m);
    if(tc_passes>i)
     tc_passes=i;
   }
  }
 }
 while(i>0)
 {
  i--;
  pm=m;
  m++;
  n_passes=tc_passes;
  f_dicpos=dicpos;
  if((r_ax=upd_tree(m))>i)
   r_ax=tc_passes=i;
  if(n_passes<THRESHOLD||(n_passes==THRESHOLD&&f_dicpos>16384)||--r_ax>n_passes||(r_ax==n_passes&&dicpos>>1<f_dicpos))
  {
   output_opt(tree[pm]);
  }
  else
  {
   i-=n_passes-1;
   m+=n_passes-1;
   r_ax=n_passes+UCHAR_MAX-2;
   output(r_ax, f_dicpos);
   if((r_ax=upd_tree(m))>i)
    tc_passes=i;
  }
 }
 huf_encode_end();
 #ifdef ASM8086
  farfree_based(ftree);
 #else
  farfree(ftree);
 #endif
 farfree(fpbuf);
 free(tree);
 tree=NULL;
}

/* Encoding stub for -m3 */

static void NEAR huf_encode_m3()
{
 int hash_bits;
 unsigned short fp_max;
 int i, j, m;
 unsigned short t;                      /* Exchange variable */
 short k, l;
 int tree_el;
 unsigned int fetch;
 unsigned char *tptr;
 unsigned short r_cx, r_dx;
 short r_ax;

 hash_bits=(dicbit+2)/3;
 fpcount=1U<<dicbit;
 fp_max=fpcount-1;
 if(tree==NULL)
 {
  if((tree=calloc(treesize+2, sizeof(*tree)))==NULL)
   error(M_OUT_OF_NEAR_MEMORY);
  #ifdef ASM8086
   ftree=farcalloc_based((unsigned long)treesize+16L, sizeof(*ftree));
   dtree=(FP_OFF(ftree)==0)?ftree:MK_FP(FP_SEG(ftree)+((FP_OFF(ftree)+15)>>4), 0);
  #else
   ftree=dtree=farcalloc((unsigned long)treesize+16L, sizeof(*ftree));
  #endif
  fpbuf=farcalloc((unsigned long)fpcount+4L, 2L);
  if(ftree==NULL||fpbuf==NULL)
   error(M_OUT_OF_MEMORY);
 }
 allocate_memory();
 display_indicator(encoded_bytes=0L);
 j=0;
 while(!unpackable)
 {
  tree_el=0;
  if(dic_alloc!=0&&j!=0)
  {
   tree_el=dic_alloc;
   if((k=j-tree_el)<=0)
   {
    k=0;
    tree_el=j;
   }
   else
    memmove(tree, tree+k, tree_el);
  }
  fetch=(unsigned int)(treesize-tree_el);
  if(multivolume_option)
   fetch=check_multivolume(fetch);
  if((fetch=fetch_uncomp(tree+tree_el, fetch))==0)
   break;
  else
  {
   j=fetch+tree_el;
   encoded_bytes+=(unsigned long)fetch;
   display_indicator(encoded_bytes);
   fill_fpbuf();
   l=fetch;
   tptr=tree;
   r_dx=(unsigned short)*(tptr++);
   r_cx=(fp_max&0xFF00)|(hash_bits&0xFF);
   r_dx<<=(hash_bits&0xFF);
   r_dx^=(unsigned short)*(tptr++);
   r_dx&=(r_cx|0xFF);
   for(m=0; m<j; m++)
   {
    r_dx<<=(r_cx&0xFF);
    r_dx^=*(tptr++);
    r_dx&=(r_cx|0xFF);
    t=fpbuf[r_dx];
    fpbuf[r_dx]=m;
    dtree[m]=t;
   }
   i=l;
   m=tree_el;
   while(i>0)
   {
    r_ax=upd_tree(m);
    if((r_ax=upd_tree(m))>i)
     r_ax=tc_passes=i;
    if(r_ax<THRESHOLD)
    {
     r_ax=(unsigned short)tree[m];
     output(r_ax, 0);
     m++;
     i--;
    }
    else
    {
     r_ax+=UCHAR_MAX-2;
     output(r_ax, dicpos);
     m+=tc_passes;
     i-=tc_passes;
    }
   }
  }
 }
 huf_encode_end();
 #ifdef ASM8086
  farfree_based(ftree);
 #else
  farfree(ftree);
 #endif
 farfree(fpbuf);
 free(tree);
 tree=NULL;
}

/* Encodes a single file. */

void encode(int method)
{
 char *dsw;                             /* Debug switch (-hd) pointer */
 char a;

 numchars=UCHAR_MAX+5;
 dicbit=14;
 dic_alloc=DICSIZ;
 treesize=31744;
 dicsiz_cur=DICSIZ-2;
 adjust_dicbit();
 /* Method 0 (store) is already filtered away at this point */
 switch(method)
 {
  case 1:
   numchars=UCHAR_MAX+5;
   break;
  case 2:
   treesize=30720;
   numchars=72;
   dic_alloc=20480;
   break;
  case 3:
   treesize=30720;
   numchars=32;
   dic_alloc=8192;
   break;
  default:
   error(M_UNKNOWN_METHOD);
 }
 switch(max_compression)
 {
  case 1:
   numchars=3000;
   dic_alloc=DICSIZ+512;
   break;
  case 2:
   numchars=512;
   dic_alloc=DICSIZ+512;
   break;
  case 3:
   numchars=1024;
   dicbit=12;
   treesize=20480;
   dicsiz_cur=dic_alloc=16384;
   break;
  case 4:
   numchars=1024;
   dicbit=12;
   treesize=12288;
   dicsiz_cur=dic_alloc=8192;
 }
 if(debug_enabled)
 {
  dsw=debug_opt;
  while(*dsw!='\0')
  {
   a=*(dsw++);
   switch(a)
   {
    case 'd':                           /* Dictionary size */
     dicsiz_cur=(unsigned int)strtol(dsw, &dsw, 10);
     break;
    case 'g':                           /* G-size */
     dic_alloc=(int)strtol(dsw, &dsw, 10);
     break;
    case 'h':
     dicbit=(int)strtol(dsw, &dsw, 10);
     break;
    case 'm':
     numchars=(int)strtol(dsw, &dsw, 10);
     break;
    case 'w':
     treesize=(int)strtol(dsw, &dsw, 10);
     break;
   }
  }
  if(strchr(debug_opt, 'v')!=NULL)
   msg_cprintf(0, M_PRECOMP_STAT, numchars, dicbit, dicsiz_cur, dic_alloc, treesize);
 }
 if(dicsiz_cur>DICSIZ_MAX)
  error(M_LARGE_DICTIONARY);
 if(dic_alloc>treesize)
  error(M_LARGE_GSIZE);
 if(method==3)
  huf_encode_m3();
 else
  huf_encode();
}

/* Fast search stub for method 4 */

static void enc4_pass1(int n_c)
{
 #ifdef ASM8086
  asm{
                mov     dx, n_c
                mov     bx, 1
                mov     cx, 0
                cmp     dx, bx
                jl      cease_search
  }
binsearch:
  asm{
                sub     dx, bx
                inc     cx
                shl     bx, 1
                cmp     dx, bx
                jl      cease_search
                sub     dx, bx
                inc     cx
                shl     bx, 1
                cmp     dx, bx
                jl      cease_search
                sub     dx, bx
                inc     cx
                shl     bx, 1
                cmp     dx, bx
                jl      cease_search
                sub     dx, bx
                inc     cx
                shl     bx, 1
                cmp     dx, bx
                jl      cease_search
                sub     dx, bx
                inc     cx
                shl     bx, 1
                cmp     dx, bx
                jl      cease_search
                jmp     binsearch
  }
cease_search:
  asm{
                or      cx, cx
                jz      chk_ctr_bounds
                push    dx
                push    cx
                mov     ax, 65535
                push    ax
                push    cx
                call    far ptr putbits
                add     sp, 4
                pop     cx
                pop     dx
  }
chk_ctr_bounds:
  asm{
                cmp     cx, 7
                jge     p1exit
                inc     cx
  }
p1exit:
  asm{
                push    dx
                push    cx
                call    far ptr putbits
                add     sp, 4
  }
 #else
  short r_bx=1;
  int r_cx=0;

  while(n_c>=r_bx)
  {
   n_c-=r_bx;
   r_cx++;
   r_bx<<=1;
  }
  if(r_cx!=0)
   putbits(r_cx, -1);
  if(r_cx<7)
   r_cx++;
  putbits(r_cx, n_c);
 #endif
}

/* Dictionary position lookup */

static void enc4_pass2(int n_c)
{
 #ifdef ASM8086
  asm{
                mov     dx, n_c
                mov     bx, 512
                mov     cx, 9
                cmp     dx, bx
                jl      p2_cease_search
  }
p2_bsearch:
  asm{
                sub     dx, bx
                inc     cx
                shl     bx, 1
                cmp     dx, bx
                jl      p2_cease_search
                sub     dx, bx
                inc     cx
                shl     bx, 1
                cmp     dx, bx
                jl      p2_cease_search
                sub     dx, bx
                inc     cx
                shl     bx, 1
                cmp     dx, bx
                jl      p2_cease_search
                sub     dx, bx
                inc     cx
                shl     bx, 1
                cmp     dx, bx
                jl      p2_cease_search
                sub     dx, bx
                inc     cx
                shl     bx, 1
                cmp     dx, bx
                jge     p2_bsearch
  }
p2_cease_search:
  asm{
                mov     ch, cl
                sub     cl, 9
                jz      p2_chk_ctr
                push    cx
                push    dx
                mov     ax, 65535
                push    ax
                push    cx
                call    far ptr putbits
                add     sp, 4
                pop     dx
                pop     cx
  }
p2_chk_ctr:
  asm{
                cmp     ch, 13
                jge     p2exit
                inc     ch
  }
p2exit:
  asm{
                mov     cl, ch
                push    dx
                push    cx
                call    far ptr putbits
                add     sp, 4
  }
 #else
  unsigned short r_bx=1<<9;
  int r_cx=9;

  while(n_c>=r_bx)
  {
   n_c-=r_bx;
   r_cx++;
   r_bx<<=1;
  }
  if(r_cx!=9)
   putbits(r_cx-9, -1);
  if(r_cx<13)
   r_cx++;
  putbits(r_cx, n_c);
 #endif
}

/* Encodes a single file, using method 4 */

void encode_f()
{
 int fetch;
 int hash_bits;
 unsigned short fp_max;
 unsigned char *tptr;
 int i, m;
 unsigned short r_cx, r_dx, r_ax;
 unsigned short t;

 dicbit=14;
 numchars=32;
 dicsiz_cur=15800;
 treesize=30720;
 adjust_dicbit();
 hash_bits=(dicbit+2)/3;
 fpcount=1U<<dicbit;
 fp_max=fpcount-1;
 if(tree==NULL)
 {
  if((tree=calloc(treesize+2, sizeof(*tree)))==NULL)
   error(M_OUT_OF_NEAR_MEMORY);
  #ifdef ASM8086
   ftree=farcalloc_based((unsigned long)treesize+16L, sizeof(*ftree));
   dtree=(FP_OFF(ftree)==0)?ftree:MK_FP(FP_SEG(ftree)+((FP_OFF(ftree)+15)>>4), 0);
  #else
   ftree=dtree=farcalloc((unsigned long)treesize+16L, sizeof(*ftree));
  #endif
  fpbuf=farcalloc((unsigned long)fpcount+4L, 2L);
  if(ftree==NULL||fpbuf==NULL)
   error(M_OUT_OF_MEMORY);
 }
 init_putbits();
 cpos=0;
 display_indicator(encoded_bytes=0L);
 while(!unpackable)
 {
  fetch=treesize;
  if(multivolume_option)
   fetch=check_multivolume(fetch);
  if((fetch=fetch_uncomp(tree, fetch))==0)
   break;
  encoded_bytes+=(unsigned long)fetch;
  display_indicator(encoded_bytes);
  fill_fpbuf();
  m=0;
  tptr=tree;
  r_dx=(unsigned short)*(tptr++);
  r_cx=(fp_max&0xFF00)|(hash_bits&0xFF);
  r_dx<<=(hash_bits&0xFF);
  r_dx^=(unsigned short)*(tptr++);
  r_dx&=(r_cx|0xFF);
  for(m=0; m<fetch; m++)
  {
   r_dx<<=(r_cx&0xFF);
   r_dx^=(unsigned char)*(tptr++);
   r_dx&=(r_cx|0xFF);
   t=fpbuf[r_dx];
   fpbuf[r_dx]=m;
   dtree[m]=t;
  }
  m=0;
  i=fetch;
  while(i>0)
  {
   if((r_ax=upd_tree(m))>i)
    r_ax=tc_passes=i;
   if(r_ax<THRESHOLD)
   {
    putbits(9, (unsigned char)tree[m]);
    i--;
    m++;
   }
   else
   {
    i-=tc_passes;
    m+=tc_passes;
    r_ax=tc_passes-2;
    enc4_pass1(r_ax);
    enc4_pass2(dicpos);
   }
  }
 }
 shutdown_putbits();
 farfree(fpbuf);
 #ifdef ASM8086
  farfree_based(ftree);
 #else
  farfree(ftree);
 #endif
 free(tree);
 tree=NULL;
}
