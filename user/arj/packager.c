/*
 * $Id: packager.c,v 1.10 2004/04/17 11:39:43 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * ARJ distribution packaging tool.
 *
 */

#include "arj.h"
#include "arjdata.h"

#if TARGET==UNIX
#include <unistd.h>
#endif

#define P PATHSEP_DEFSTR                /* Dirty hack for compaction */

#if TARGET==UNIX
 #define REGWIZ       "arj-register"
#else
 #define REGWIZ           "register"
#endif

/* mkdir() macro */

#if TARGET==UNIX||defined(__EMX__)
 #define md(p) mkdir(p, 0755)
#else
 #define md(p) mkdir(p)
#endif

static char strform[]="%s";
static char sfx_name[16];
static char buf[2048];
static char l_nullstr[]="";

/* Q&D tolower() */

static void arj_strlwr(char *str)
{
 char p;

 while((p=*str)!='\0')
 {
  if(p>='A'&&p<='Z')
  {
   p+=32;
   *str=p;
  }
  str++;
 }
}

/* A smart fopen() */

static FILE *s_fopen(char *name, char *mode)
{
 FILE *rc;

 if((rc=fopen(name, mode))==NULL)
 {
  printf("Can't open %s\n", name);
  exit(2);
 }
 return(rc);
}

/* Line-by-line output routine. Involves macro expansion. */

static void out_line(FILE *stream, char *str)
{
 strcpyn(buf, str, sizeof(buf));
 expand_tags(buf, sizeof(buf));
 fprintf(stream, strform, buf);
}

/* Transfer a file, expanding the tags */

static void transfer_file(char *dest, char *src)
{
 FILE *istream;
 FILE *ostream;

 istream=s_fopen(src, "r");
 ostream=s_fopen(dest, "w");
 while(fgets(buf, sizeof(buf), istream))
 {
  expand_tags(buf, sizeof(buf));
  fputs(buf, ostream);
 }
 fclose(istream);
 fclose(ostream);
}

/* Packages a binary or other file, transforming to a UNIX-style path */

#if TARGET==UNIX
static void package_unix(FILE *stream, char *name, char *trunk, char *realpath, char *unixpath)
{
 char realname[CCHMAXPATH], unixname[CCHMAXPATH];

 /* Compose the trunk path, e.g. "freebsd3.4/en/rc/" */
 strcpy(realname, trunk);
 strcpy(unixname, trunk);
 strcat(realname, P);
 strcat(unixname, P);
 /* Now, make "freebsd3.4/en/rc/arj" and "freebsd3.4/en/rc/u/bin" */
 strcat(realname, realpath);    /* arj */
 if(realpath[0]!='\0')
  strcat(realname, P);
 strcat(unixname, "u");         /* u */
 md(unixname);
 strcat(unixname, P);
 strcat(unixname, unixpath);    /* u/bin */
 md(unixname);
 strcat(unixname, P);
 /* Append the names */
 strcat(realname, name);
 strcat(unixname, name);
 unlink(unixname);
 if(link(realname, unixname))
 {
  printf("Failed to link <%s> to <%s>\n", realname, unixname);
  exit(1);
 }
 fprintf(stream, "%s" P "%s\n", unixpath, name);
}

#endif

/* Arranges text file packaging (realpath -> resource, trunk -> compiler/en/rc/...) */

static void package_txt(FILE *stream, char *name, char *trunk, char *realpath, char *unixpath)
{
 char tmp_name[CCHMAXPATH], realname[CCHMAXPATH];
 char *p;

 strcpy(tmp_name, trunk);
 strcat(tmp_name, P);
 strcat(tmp_name, name);
 strcpy(realname, realpath);
 strcat(realname, P);
 strcat(realname, name);
 transfer_file(tmp_name, realname);
 #if TARGET==UNIX
  package_unix(stream, name, trunk, "", unixpath);
 #else
  fprintf(stream, "%s\n", tmp_name);
 #endif
}

/* Arranges binary file packaging (realpath -> arj, trunk -> compiler/en/rc/...) */

static void package_bin(FILE *stream, char *name, char *trunk, char *realpath, char *unixpath)
{
 #if TARGET==UNIX
  package_unix(stream, name, trunk, realpath, unixpath);
 #else
  fprintf(stream, "%s" P "%s" P "%s\n", trunk, realpath, name);
 #endif
}

/* Comment creation routine */

static void create_cmt(char *dest)
{
 FILE *stream;
 /* Output path tricks */
 #if TARGET==UNIX
  char subdir[]="/usr/local/";
 #elif TARGET==OS2
  char subdir[]="C:" P "ARJ" P "OS2" P; /* Historical (since ARJ/2 v 2.61) */
 #elif TARGET==DOS||TARGET==WIN32
  char subdir[]="C:" P "ARJ" P;
 #endif
 char tmp_str[128], out_str[128];
 int i, l;

 stream=s_fopen(dest, "w");
 fprintf(stream, ")) %s -m -b -x\n\n", subdir);
 /* Version string */
 sprintf(tmp_str, "%s",
 #if LOCALE==LANG_en
  #if TARGET==DOS
   "ARJ v @VERSION manufacturing refresh by ARJ Software Russia  All rights reserved"
  #else
   "@PRODUCT v @VERSION, (c) 1998-@{y}, ARJ Software Russia. All rights reserved."
  #endif
 #elif LOCALE==LANG_de
  #if TARGET==DOS
   "ARJ @VERSION Produktionsauffrischung, ARJ Software Russia  Alle Rechte vorbehalten"
  #else
   "ARJ fБr @PLATFORM @VERSION (c) 1998-@{y}, ARJ Software Russia. Alle Rechte vorbehalten."
  #endif
 #elif LOCALE==LANG_ru
  "ARJ v @VERSION, (c) 1998-@{y}, ARJ Software Russia."
 #endif
 );
 expand_tags(tmp_str, sizeof(tmp_str));
 sprintf(out_str, "@{c40}%s@{_}\n", tmp_str);
 out_line(stream, out_str);
 l=strlen(tmp_str);
 for(i=0; i<l; i++)
  tmp_str[i]='_';
 sprintf(out_str, "@{c40}%s@{_}\n", tmp_str);
 out_line(stream, out_str);
 out_line(stream, "\n");
 /* Distribution area */
 #ifndef DEBUG
  sprintf(tmp_str, "@{c40}%s@{_}\n",
  #if LOCALE==LANG_en
   "*** For World-wide use and distribution ***"
  #elif LOCALE==LANG_de
   "*** FБr weltweiten Einsatz und Vertrieb ***"
  #elif LOCALE==LANG_ru
   /* All correct here, Russian NLV contains strong encryption so we limit it
      to domestic distribution */
   "*** Для распространения на территории РФ ***"
  #endif
  );
 #endif
 /* Intro */
 out_line(stream,
  "\n"
 #if LOCALE==LANG_en
  "  ARJ is a disk space saving file archiver with many file management functions."
 #elif LOCALE==LANG_de
  "  ARJ archiviert Dateien in Speicherplatz sparende, komprimierte Archive."
 #elif LOCALE==LANG_ru
  "  ARJ - программа для ведения архивов (наборов сжатых файлов)."
 #endif
 "\n\n"
 );
 /* Feature list */
 out_line(stream,
 #if LOCALE==LANG_en
  "  NEW FEATURES OF ARJ INCLUDE:\n"
  "\n"
  "  Native versions for UNIX-like operating systems.\n"
  "  Support for archiving more than 65000 files.\n"
  "  ARJ self-extractor post extraction command execution option.\n"
  "  ARJ self-extractor automatic password prompt for garbled archives.\n"
  "  Option to select files with long filenames within an archive.\n"
  "  Handling of file ownership, UNIX special files, EAs and file access time.\n"
 #elif LOCALE==LANG_de
  /* BUGBUG: update this! */
  "  NEUE FUNKTIONEN VON ARJ BEINHALTEN:\n"
  "\n"
  "  ARJ Selbst-Entpacker Post-Entpack-Programmaufruf MФglichkeit.\n"
  "  ARJ Selbst-Entpacker automatische Passwort-Eingabe fБr geschБtzte Archive.\n"
  "  MФglichkeit Dateien mit langem Dateinamen in einem Archiv auszuwДhlen.\n"
  "  UnterstБtzung erweiterter Attribute und Zeitstempel.\n"
 #elif LOCALE==LANG_ru
  "  НОВЫЕ ВОЗМОЖНОСТИ ARJ ВКЛЮЧАЮТ В СЕБЯ:\n"
  "\n"
  "  Версии для операционных систем семейства UNIX\n"
  "  Архивацию более 65000 файлов\n"
  "  Возможность фиксации ключей для самораспаковывающихся архивов.\n"
  "  Автоматический запрос пароля при работе с зашифрованными файлами.\n"
  "  Ключи для отбора файлов с длинными именами из архива.\n"
  #if TARGET==DOS
   "  Поддержку длинных имен, расширенных атрибутов и специальных файлов UNIX.\n"
  #elif TARGET==OS2
   "  Поддержку специальных файлов и атрибутов UNIX, EA и даты доступа к файлу.\n"
  #endif
 #endif
  "\n"
 );
 /* Packaging hints */
 out_line(stream,
 #if LOCALE==LANG_en
  "  This is a self-extracting archive. Run it to extract all files.\n"
  "  The file names in this archive are the same as in ARJ @COUNTERPARTS for DOS.\n"
 #elif LOCALE==LANG_de
  "  Dies ist ein selbst-entpackendes Archiv-'ARJ2G281' zum Entpacken aller Dateien.\n"
  "  Die Dateinamen in diesem Archiv sind die gleichen, wie in ARJ @COUNTERPARTS fБr DOS.\n"
 #elif LOCALE==LANG_ru
  "  Это самораспаковывающийся архив. Запустите его, чтобы распаковать все файлы.\n"
  "  Файлы в архиве совпадают по именам с ARJ v @COUNTERPARTS для DOS.\n"
 #endif
 );
 /* README hint */
 out_line(stream,
 #if LOCALE==LANG_en
  "  Please read README.TXT and @PLATFORM_FN.TXT for important update information!\n"
 #elif LOCALE==LANG_de
  "  Bitte die README.TXT fБr wichtige Informationen zum Update lesen!\n"
 #elif LOCALE==LANG_ru
  "  Важная информация об обновлениях содержится в файлах README.TXT и @PLATFORM_FN.TXT\n"
 #endif
 );
 fclose(stream);
}

/* Main routine */

int main(int argc, char **argv)
{
 #ifndef COMMERCIAL
  char family_tag[]="arj";
 #else
  char family_tag[]="com";
 #endif
 #if TARGET==DOS
  char os_tag='_';
 #elif TARGET==OS2
  char os_tag='2';
 #elif TARGET==WIN32
  char os_tag='w';
 #elif defined(linux)
  char os_tag='l';
 #elif defined(__FreeBSD__)
  char os_tag='f';
 #elif defined(__QNXNTO__)
  char os_tag='q';
 #elif defined(SUNOS)
  char os_tag='s';
 #else
  char os_tag='x';
 #endif
 #if LOCALE==LANG_en
  char lang_tag='_';
 #elif LOCALE==LANG_fr
  char lang_tag='f';
 #elif LOCALE==LANG_de
  char lang_tag='g';
 #elif LOCALE==LANG_ru
  char lang_tag='r';
 #endif
 char version_tag[8];
 char *p, *pname, *ppath;
 FILE *istream, *ostream;
 static char pkg_rsp_draft[CCHMAXPATH], pkg_rsp[CCHMAXPATH];
 static char tmp_name[CCHMAXPATH];
 static char cmdline[CMDLINE_MAX], arj_cmds[CMDLINE_MAX];
 char platform_specific[CCHMAXPATH];

 printf("PACKAGER v 2.15c  [27/06/2003]  Not a part of any binary package!\n\n");
 if(argc<3)
 {
  printf("Usage: PACKAGER <builder directory> <work directory>,\n"
         "       e.g, PACKAGER msc6_os2/en/rc/arj msc6_os2/en/ds/arj\n"
         "\n"
         "This program finalizes the resources and performs packaging of the given brach.\n");
  exit(1);
 }
 strcpy(buf, "@VERSION");
 expand_tags(buf, sizeof(buf)-1);
 if((p=strchr(buf, '.'))!=NULL)
 {
  strcpy(p, p+1);
  if((p=strchr(buf, '.'))!=NULL)
   *p='\0';
 }
 memset(version_tag, 0, sizeof(version_tag));
 memcpy(version_tag, buf, 3);
 sprintf(pkg_rsp_draft, "%s" P "pkg_dft.rsp", argv[2]);
 sprintf(pkg_rsp, "%s" P "pkg.rsp", argv[2]);
 sprintf(tmp_name, "%s" P "cmt.txt", argv[2]);
 create_cmt(tmp_name);
 ostream=s_fopen(pkg_rsp_draft, "w");
 sprintf(sfx_name, "%s%c%c%s", family_tag, os_tag, lang_tag, version_tag);
 /* Flush the main line */
 #ifdef DEBUG
  #if defined(linux)
   strcpy(buf, ".lnx");
  #elif defined(__FreeBSD__)
   strcpy(buf, ".bsd");
  #elif defined(__QNXNTO__)
   strcpy(buf, ".qnx");
  #else
   buf[0]='\0';
  #endif
  strcat(buf, " -h#YYYYMMDD");          /* The classic debug by-date format */
 #else
  strcpy(buf, sfx_name);
 #endif
 #if TARGET==UNIX
  sprintf(platform_specific, "-e1 %s" P "u" P, argv[2]);
 #else
  strcpy(platform_specific, "-e");
 #endif
 /* Dispose of previous package */
 sprintf(arj_cmds, "retail" P "%s" EXE_EXTENSION, buf);
 unlink(arj_cmds);
 /* "-hz" removed - no commercial versions */
 sprintf(arj_cmds, "a -2e.*TYPE -jm -z%s -y -je -va retail" P "%s %s", tmp_name, buf, platform_specific);
 /* Create doc repository */
 #if TARGET==UNIX
  sprintf(platform_specific, "%s" P "u", argv[2]);
  md(platform_specific);
  strcat(platform_specific, P "doc");
  md(platform_specific);
 #endif
 /* Proceed with the files */
 package_bin(ostream, "arj" EXE_EXTENSION, argv[2], "arj", "bin");
 #if LOCALE==LANG_ru
  package_bin(ostream, "arjcrypt" MOD_EXTENSION, argv[2], "arjcrypt", "lib");
 #endif
 package_bin(ostream, "rearj" EXE_EXTENSION, argv[2], "rearj", "bin");
 package_bin(ostream, REGWIZ EXE_EXTENSION, argv[2], "register", "bin");
 package_bin(ostream, "arjdisp" EXE_EXTENSION, argv[2], "arjdisp", "bin");
 #if TARGET==DOS
  /* ASR 20/02/2001 -- we were supposed to divert it for various platforms but
     it remains DOS-specific as for now */
  package_txt(ostream, "rearj.cfg", argv[2], "resource", "doc");
 #elif TARGET==UNIX
  /* Provide an InfoZIP and .tar.gz-capable configuration */
  package_txt(ostream, "rearj.cfg.example", argv[2], "resource", "doc" P "arj");
 #endif
 package_txt(ostream, "readme.txt", argv[2], "resource" P LOCALE_DESC, "doc" P "arj");
 package_txt(ostream, "history.txt", argv[2], "resource"  P LOCALE_DESC, "doc" P "arj");
 strcpy(tmp_name, "@PLATFORM_FN.txt");
 expand_tags(tmp_name, sizeof(tmp_name));
 arj_strlwr(tmp_name);
 package_txt(ostream, tmp_name, argv[2], "resource" P LOCALE_DESC, "doc" P "arj");
 package_txt(ostream, "COPYING", argv[2], "doc", "doc" P "arj");
 package_txt(ostream, "file_id.diz", argv[2], "resource" P LOCALE_DESC, "doc" P "arj");
 /* Share our secrets with the debugging team */
 #ifdef DEBUG
  package_txt(ostream, "rev_hist.txt", argv[2], "doc", "doc" P "arj");
  package_txt(ostream, "debug.txt", argv[2], "doc", "doc" P "arj");
  package_txt(ostream, "glossary.txt", argv[2], "doc", "doc" P "arj");
 #endif
 fclose(ostream);
 istream=s_fopen(pkg_rsp_draft, "r");
 ostream=s_fopen(pkg_rsp, "w");
 fprintf(ostream, "%s\n", arj_cmds);
 while(fgets(buf, sizeof(buf), istream)!=NULL)
 {
  fputs(buf, ostream);
  #ifdef MAKESYM  
   if((p=strstr(buf, EXE_EXTENSION))!=NULL||
      (p=strstr(buf, MOD_EXTENSION))!=NULL)
   {
    pname=strrchr(buf, PATHSEP_DEFAULT);
    if(pname!=NULL)
    {
     *pname++='\0';
     ppath=buf;
    }
    else
    {
     pname=buf;
     ppath=l_nullstr;
    }
    *p='\0';
    chdir(ppath);
    strcat(pname, ".map");
    if(!access(pname, 0))
    {
     fprintf(ostream, "%s" P "%s\n", ppath, pname);
     sprintf(cmdline, "mapsym %s", pname);
     system(cmdline);
     strcpy(p, ".sym");
     if(!access(pname, 0))
      fprintf(ostream, "%s" P "%s\n", ppath, pname);
    }
    if(*ppath!='\0')
    {
     p=ppath;
     do
     {
      chdir("..");
      p=strchr(p+1, PATHSEP_DEFAULT);
     } while(p!=NULL);
    }
   }
  #endif 
 }
 fclose(istream);
 fclose(ostream);
 unlink(pkg_rsp_draft);
 /* Pack the files. */
 sprintf(cmdline, "%s" P "arj" P "arj @%s -+", argv[1], pkg_rsp);
 system(cmdline);
 unlink(pkg_rsp);
 return(0);
}
