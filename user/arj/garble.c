/*
 * $Id: garble.c,v 1.7 2004/02/21 22:53:35 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * All procedures dealing  with archive data encryption are stored  here. This
 * module also references additional routines in GOST40.C.
 *
 */

#include <setjmp.h>

#include "arj.h"
#include "arjcrypt.h"
#ifdef TILED
 #include <dos.h>
#endif
#if TARGET==UNIX
 #include <dlfcn.h>
#endif

DEBUGHDR(__FILE__)                      /* Debug information block */

/* DOS constants */

#if TARGET==DOS
 #define COM_ENTRY             0x100    /* Entry point of COM file within PSP */
 #define ARJCRYPT_STACK_SIZE   0x500    /* Number of bytes to add in tail */
 #define ARJCRYPT_RESERVE       0x20    /* Size of exchange buffer */
#endif

/* Skip ARJCRYPT executable lookup if not advised to */

#ifdef SKIP_GET_EXE_NAME
 #define NO_ARJCRYPT_LOOKUP
#endif

/* Local variables */

#if SFX_LEVEL>=ARJSFXV
static int arjcrypt_loaded=0;           /* 1 if the ARJCRYPT has been loaded */
struct arjcrypt_exblock exblock;        /* Exchange block storage */
#if TARGET==DOS
 static char FAR *arjcrypt_mem;         /* Memory for ARJCRYPT module */
 static unsigned char FAR *arjcrypt_body;/* PSP-relative ARJCRYPT storage */
 static unsigned int arjcrypt_psp;      /* PSP segment of ARJCRYPT.COM */
 static int arjcrypt_entry;             /* Entry point within ARJCRYPT PSP */
 static char *arjcrypt_stack;           /* Address of stack */
 static char arjcrypt_sig[]=ARJCRYPT_SIG;/* ARJCRYPT signature */
 static jmp_buf arjcrypt_proc;          /* Address of ARJCRYPT invocation */
 static unsigned short ret_sp;
#elif TARGET==OS2
 HMODULE arjcrypt_hmod;                 /* OS/2 DLL handle */
 #ifdef __32BIT__
  int (* EXPENTRY arjcrypt_entry) (struct arjcrypt_exblock FAR *exblock_ptr);
 #else
  VOID (FAR PASCAL *arjcrypt_entry) (struct arjcrypt_exblock FAR *exblock_ptr);
 #endif
#elif TARGET==WIN32
 HINSTANCE arjcrypt_hmod;               /* Win32 DLL handle */
 VOID (*arjcrypt_entry) (struct arjcrypt_exblock FAR *exblock_ptr);
#elif TARGET==UNIX
 void *arjcrypt_hmod;
 int (*arjcrypt_entry) (struct arjcrypt_exblock *exblock_ptr);
#endif
#endif
static char *tmp_pwd_ptr;               /* Active pointer to the password */

#if SFX_LEVEL>=ARJSFXV

/* Moves the ARJCRYPT module to an area suitable for COM file storage */

#if TARGET==DOS
static void relocate_arjcrypt(char FAR *dest, char FAR *src, int len)
{
 while((len--)>0)
  *(dest++)=*(src++);
}
#endif

/* Minimizes the offset portion of FAR pointer given */

#if TARGET==DOS
static char FAR *adjust_segment(char FAR *long_addr)
{
 return((char FAR *)((unsigned long)((FP_OFF(long_addr)>>4)+((unsigned long)FP_SEG(long_addr))<<16)+(unsigned long)(FP_SEG(long_addr)%16)));
}
#endif

/* Unloads ARJCRYPT module upon exit */

#if TARGET==OS2||TARGET==WIN32||TARGET==UNIX
static void remove_arjcrypt()
{
 if(arjcrypt_loaded)
 {
  #if TARGET==OS2
   DosFreeModule(arjcrypt_hmod);
  #elif TARGET==WIN32
   FreeLibrary(arjcrypt_hmod);
  #elif TARGET==UNIX
   dlclose(arjcrypt_hmod);
  #endif
 }
 arjcrypt_loaded=0;
}
#endif

/* Initializes the ARJCRYPT interface. Returns a non-zero value if something
   went wrong. */

static int arjcrypt_init(char *name)
{
 FILE *stream;
 int arjcrypt_size;                     /* Size of ARJCRYPT module */
 char *tmp_cryptmem;                    /* Temporary storage for ARJCRYPT */
 #if TARGET==DOS
  int cur_pos;                          /* Current position within PSP */
  int i;
 #endif

#ifndef NO_ARJCRYPT_LOOKUP
 stream=file_open_noarch(name, m_rb);
 fclose(stream);
 if(!check_integrity(name))
  msg_cprintf(0, M_NONSTD_GARBLE);
 stream=file_open_noarch(name, m_rb);
 fseek(stream, 0L, SEEK_END);
 arjcrypt_size=(int)ftell(stream);
 rewind(stream);
 tmp_cryptmem=malloc_msg(arjcrypt_size+2);
 fread(tmp_cryptmem, 1, arjcrypt_size, stream);
 fclose(stream);
 #if TARGET==DOS
  arjcrypt_mem=farmalloc_msg(arjcrypt_size+ARJCRYPT_STACK_SIZE+0x10);
  arjcrypt_body=adjust_segment(arjcrypt_mem);
  arjcrypt_psp=FP_SEG(arjcrypt_body)+1;  /* Workaround for MS C v 7.0 macro */
  arjcrypt_body=(char FAR *)((unsigned long)arjcrypt_psp<<16);
  relocate_arjcrypt(arjcrypt_body+COM_ENTRY, (char FAR *)tmp_cryptmem, arjcrypt_size);
 #endif
 free(tmp_cryptmem);
#endif
 #if TARGET==DOS
  arjcrypt_entry=-1;
  for(cur_pos=COM_ENTRY; cur_pos<=arjcrypt_size+COM_ENTRY; cur_pos++)
  {
   for(i=0; arjcrypt_sig[i]!='\0'; i++)
   {
    if(arjcrypt_sig[i]!=arjcrypt_body[cur_pos+i])
     break;
   }
   /* If the signature matched */
   if(arjcrypt_sig[i]=='\0')
   {
    arjcrypt_entry=((int)arjcrypt_body[cur_pos+i+2]<<8)+(int)arjcrypt_body[cur_pos+i+1];
    break;
   }
  }
  if(arjcrypt_entry==-1)
   error(M_NO_ARJCRYPT_ENTRY);
  /* Calculate exchange buffer address (DWORD-aligned) */
  arjcrypt_stack=(char *)((arjcrypt_size+ARJCRYPT_STACK_SIZE-ARJCRYPT_RESERVE)&~3);
 #elif TARGET==OS2
  if(DosLoadModule(NULL, 0, name, &arjcrypt_hmod))
   error(M_ARJCRYPT_ERROR);
  atexit(remove_arjcrypt);
  #ifdef __32BIT__
   if(DosQueryProcAddr(arjcrypt_hmod, 1L, NULL, (PFN *)&arjcrypt_entry))
    error(M_NO_ARJCRYPT_ENTRY);
  #else
   if(DosGetProcAddr(arjcrypt_hmod, (PSZ)1L, &arjcrypt_entry))
    error(M_NO_ARJCRYPT_ENTRY);
  #endif
 #elif TARGET==WIN32
  if((arjcrypt_hmod=LoadLibrary(name))==NULL)
   error(M_ARJCRYPT_ERROR);
  atexit(remove_arjcrypt);
  if((arjcrypt_entry=(VOID *)GetProcAddress(arjcrypt_hmod, (LPCSTR)1L))==NULL)
   error(M_NO_ARJCRYPT_ENTRY);
 #elif TARGET==UNIX
  if((arjcrypt_hmod=dlopen(name, RTLD_NOW))==NULL)
  {
   #ifdef DEBUG
    fputs(dlerror(), new_stdout);
   #endif
   error(M_ARJCRYPT_ERROR);
  }
  if((arjcrypt_entry=dlsym(arjcrypt_hmod, "entry"))==NULL)
   error(M_NO_ARJCRYPT_ENTRY);
 #endif
 return(0);
}

/* Transfers control to the ARJCRYPT invocation point. Never returns. */

#if TARGET==DOS
static int FAR return_from_arjcrypt()
{
 /* Restore our DS after being trashed by ARJCRYPT. longjmp() will do the
    rest. */
 #if COMPILER==BCC
  #ifdef __BORLANDC__
   asm{
    mov   ax, seg arjcrypt_proc
   }
  #else
   asm{
    mov   ax, seg _DATA
   }
  #endif
 #elif COMPILER==MSC
  asm{
   cli
   mov   ax, SEG arjcrypt_proc
   mov   ss, ax
   mov   sp, word ptr ss:ret_sp
   sti
  }
 #endif
 asm{
  mov   ds, ax
 }
 longjmp(arjcrypt_proc, 1);
 return(0);
}
#endif

/* Invokes ARJCRYPT */

static int invoke_arjcrypt()
{
 struct arjcrypt_exblock FAR *exblock_ptr;

 exblock.rc=ARJCRYPT_RC_OK;
 #if TARGET==DOS
  exblock.ret_addr=&return_from_arjcrypt;
 #endif
 exblock_ptr=(struct arjcrypt_exblock FAR *)&exblock;
 #if TARGET==DOS
  if(!setjmp(arjcrypt_proc))
  {
   asm{
    mov word ptr ret_sp, sp
    mov cx, word ptr exblock_ptr+2
    mov dx, word ptr exblock_ptr
    mov ax, arjcrypt_psp
    mov bx, arjcrypt_stack
    mov si, arjcrypt_entry
    mov es, ax
    mov ds, ax
    cli
    mov ss, ax
    mov sp, bx
    sti
    push ax
    push si
    retf
   }
  }
 #elif TARGET==OS2||TARGET==WIN32
  arjcrypt_entry(exblock_ptr);
 #elif TARGET==UNIX
  (*arjcrypt_entry)(exblock_ptr);
 #endif
 return(exblock.rc);
}

#endif

/* Initializes the encryption subsystem */

int garble_init(char modifier)
{
 #if SFX_LEVEL>=ARJSFXV
  char tmp_arjcrypt_name[CCHMAXPATH];
 #endif

 #if SFX_LEVEL>=ARJSFXV
  if(ext_hdr_flags==ENCRYPT_STD||ext_hdr_flags==ENCRYPT_OLD)
  {
   password_modifier=modifier;
   tmp_pwd_ptr=garble_password;
   return(ENCRYPT_STD);
  }
  /* 40-bit encryption is not supported by SFX */
  #if SFX_LEVEL>=ARJ
  else if(ext_hdr_flags==ENCRYPT_GOST40)
  {
   gost40_init(modifier);
   return(ENCRYPT_GOST40);
  }
  #endif
  else                                   /* Assume that ARJCRYPT is needed */
  {
   if(!arjcrypt_loaded)
   {
    tmp_arjcrypt_name[0]='\0';
    if(arjcrypt_name!=NULL&&split_name(arjcrypt_name, NULL, NULL)>0)
     strcpy(tmp_arjcrypt_name, arjcrypt_name);
    else
    {
     /* Get pathname of executable */
     #if !defined(SKIP_GET_EXE_NAME)
      split_name(exe_name, tmp_arjcrypt_name, NULL);
     #elif defined(PKGLIBDIR)
      /* if !defined(PKGLIBDIR), we'll let the dynamic loader perform the
         search */
      strcpy(tmp_arjcrypt_name, PKGLIBDIR);
      strcat(tmp_arjcrypt_name, "/");
     #endif
     if(arjcrypt_name==NULL||arjcrypt_name[0]=='\0')
      msg_strcat(tmp_arjcrypt_name, M_ARJCRYPT_COM);
     else
      strcat(tmp_arjcrypt_name, arjcrypt_name);
     #if TARGET==UNIX
      strcat(tmp_arjcrypt_name, MOD_EXTENSION);
     #endif
    }
    msg_cprintf(0, M_LOADING, tmp_arjcrypt_name);
    arjcrypt_init(tmp_arjcrypt_name);
   }
   arjcrypt_loaded=1;
   exblock.mode=ARJCRYPT_V2_INIT;
   exblock.inq_type=ARJCRYPT_INQ_INIT;
   exblock.flags=ext_hdr_flags;
   exblock.password=(char FAR *)garble_password;
   exblock.l_modifier[0]=garble_ftime;
   exblock.l_modifier[1]=(long)(signed char)modifier;
   return(invoke_arjcrypt());
  }
 #else
  password_modifier=modifier;
  tmp_pwd_ptr=garble_password;
  return(ENCRYPT_STD);
 #endif
}

#if SFX_LEVEL>=ARJ

/* Encodes a block of data */

void garble_encode(char *data, int len)
{
 int i;
 char *tmp_dptr;

 tmp_dptr=data;
 /* Standard encryption */
 if(ext_hdr_flags==ENCRYPT_STD||ext_hdr_flags==0)
 {
  for(i=0; i<len; i++)
  {
   *(tmp_dptr++)^=(password_modifier+*(tmp_pwd_ptr++));
   if(*tmp_pwd_ptr=='\0')
    tmp_pwd_ptr=garble_password;         /* Rewind the pointer */
  }
 }
 /* GOST-40 encryption (v 2.61+) */
 else if(ext_hdr_flags==ENCRYPT_GOST40)
  gost40_encode_stub(data, len);
 /* GOST 256-bit encryption (v 2.55+) */
 else
 {
  if(!arjcrypt_loaded)
   error(M_ARJCRYPT_ERROR);
  exblock.mode=ARJCRYPT_ENCODE;
  exblock.len=len;
  exblock.data=(char FAR *)data;
  invoke_arjcrypt();
 }
}

#endif

/* Decodes a block of data */

void garble_decode(char *data, int len)
{
 int i;
 char *tmp_dptr;

 tmp_dptr=data;
 /* Standard encryption */
 if(ext_hdr_flags==ENCRYPT_STD||ext_hdr_flags==0)
 {
  for(i=0; i<len; i++)
  {
   *(tmp_dptr++)^=(password_modifier+*(tmp_pwd_ptr++));
   if(*tmp_pwd_ptr=='\0')
    tmp_pwd_ptr=garble_password;         /* Rewind the pointer */
  }
 }
 #if SFX_LEVEL>=ARJ
 /* GOST 40-bit encryption (v 2.61+) */
 else if(ext_hdr_flags==ENCRYPT_GOST40)
  gost40_decode_stub(data, len);
 #endif
 /* GOST 256-bit encryption (v 2.55+) */
 #if SFX_LEVEL>=ARJSFXV
 else
 {
  if(!arjcrypt_loaded)
   error(M_ARJCRYPT_ERROR);
  exblock.mode=ARJCRYPT_DECODE;
  exblock.len=len;
  exblock.data=(char FAR *)data;
  invoke_arjcrypt();
 }
 #endif
}
