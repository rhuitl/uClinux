/*
 * $Id: file_reg.c,v 1.2 2003/05/03 22:18:47 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * This file contains registration-related helper procedures.
 *
 */

#include "arj.h"

DEBUGHDR(__FILE__)                      /* Debug information block */

/* Local variables */

static char special_key[]="Y2K";
#if TARGET==DOS
 static char default_key_name[]="C:ARJX";
 static char key_name[]="ARJ.KEY";
#else
 static char key_name[]="arj.key";
#endif

/* Validates registration information */

int reg_validation(char *key1, char *key2, char *name, char *validation)
{
 return(verify_reg_name(key1, key2, name, validation));
}

/* Hot-fix registration procedure */

void hot_reg(char *block)
{
 char *nptr;
 int i;

 strip_lf(block);
 nptr=block;
 if(!stricmp(block, special_key))
  in_key=0;
 for(i=0; i<8; i++)
 {
  nptr=ltrim(nptr);
  mput_dword(strtoul(nptr, &nptr, 10), (char*)&regdata[REG_HDR_SHIFT+(i<<2)]);
 }
 nptr=ltrim(nptr);
 for(i=0; *nptr!=' '&&*nptr!='\0'&&i<REG_KEY1_LEN; i++)
  regdata[REG_KEY1_SHIFT+i]=*nptr++;
 regdata[REG_KEY1_SHIFT+i]='\0';
 nptr=ltrim(nptr);
 for(i=0; *nptr!=' '&&*nptr!='\0'&&i<REG_KEY2_LEN; i++)
  regdata[REG_KEY2_SHIFT+i]=*nptr++;
 regdata[REG_KEY2_SHIFT+i]='\0';
 nptr=ltrim(nptr);
 for(i=0; *nptr!='\0'&&i<REG_NAME_LEN; i++)
  regdata[REG_NAME_SHIFT+i]=*nptr++;
 regdata[REG_NAME_SHIFT+i]='\0';
 alltrim(regdata+REG_KEY1_SHIFT);
}

/* Parses the registration key, if any */

void parse_reg_key()
{
 char *nptr;
 char key_path[FILENAME_MAX];
 char key[200];
 FILE *stream;

 if(regdata[REG_NAME_SHIFT]=='\0')
 {
  #ifndef SKIP_GET_EXE_NAME
   nptr=exe_name;
   #if TARGET==DOS
    if(_osmajor<3)
     nptr=default_key_name;
   #endif
   split_name(nptr, key_path, NULL);
   strcat(key_path, key_name);
  #else
   split_name(exe_name, key_path, NULL); /* Hack for PACKAGER */
   strcat(key_path, key_name);           /* Hack for PACKAGER */
   if(!file_exists(key_path))                      
    sprintf(key_path, "%s/.%s", getenv("HOME"), key_name);
   if(!file_exists(key_path))
    sprintf(key_path, "/etc/%s", key_name);
  #endif
  if(file_exists(key_path))
  {
   if((stream=fopen(key_path, m_r))!=NULL)
   {
    if(fgets(key, sizeof(key), stream)==NULL)
     fclose(stream);
    else
    {
     fclose(stream);
     hot_reg(key);
    }
   }
  }
 }
}
