/* Nessus Attack Scripting Language 
 *
 * Copyright (C) 2002 - 2004 Tenable Network Security
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */
#include <includes.h>

#include "nasl_tree.h"
#include "nasl_global_ctxt.h"
#include "nasl_func.h"
#include "nasl_var.h"
#include "nasl_lex_ctxt.h"
#include "exec.h"
#include "nasl_regex.h"
#include "nasl_debug.h"


#ifdef ENABLE_PLUGIN_SERVER
extern int naslparse( naslctxt * );

 	
/*---------------------------------------------------------------------------*/
struct fd_ctx {
	char * buf;
	unsigned int  allocated_size;
	unsigned int  ptr;
	};

static int fdctx_init(struct fd_ctx * ctx) 
{
 ctx->allocated_size = 512;
 ctx->ptr = 0;
 ctx->buf = emalloc(ctx->allocated_size);
 if ( ctx->buf == NULL ) 
	return -1;
 else 
	return 0;
}


static int fdctx_free(struct fd_ctx * ctx)
{
 efree(&(ctx->buf));
 ctx->ptr = ctx->allocated_size = 0;
 return 0;
}

static int fdctx_write(struct fd_ctx * ctx, const void * data, unsigned int len)
{
 if ( ctx == NULL ) 
 	return -1;
 
 if ( ctx->allocated_size < (ctx->ptr + len ) )
 {
  ctx->allocated_size *= 2;
  if ( ctx->allocated_size < ctx->ptr + len )
	ctx->allocated_size += ctx->ptr + len;

  ctx->buf = erealloc(ctx->buf, ctx->allocated_size);
 }
 
 memcpy(&ctx->buf[ctx->ptr], data, len);
 ctx->ptr += len;
 return len;
}

static int fdctx_eof(struct fd_ctx * ctx)
{
 return ctx->ptr >= ctx->allocated_size;
}



static int fdctx_read(struct fd_ctx * ctx, void * buf, unsigned int len)
{
 if ( ctx->ptr + len > ctx->allocated_size ) 
 {
	return -1;
 }
	

 memcpy(buf, &(ctx->buf[ctx->ptr]), len);
 ctx->ptr += len;
 return len;
}


static int fdctx_save(struct fd_ctx * ctx, int fd )
{
 int n = 0;
 
 while ( n != ctx->ptr )
 {
  int e = write(fd, ctx->buf + n, ctx->ptr - n);
  if ( e < 0 && errno != EINTR ) 
  {
    perror("write ");
    return  -1;
  }
  else if ( e > 0 ) n += e;
 }

 return n;
}

static int fdctx_load(struct fd_ctx * ctx, int fd)
{
 struct stat st;
 unsigned int n = 0, l;

 if ( fstat(fd, &st) < 0 )
	return -1;

 l = (unsigned int) st.st_size;
 ctx->allocated_size = l;
 ctx->buf = emalloc(l);
 ctx->ptr = 0;

 while ( n != l )
 {
  int e;
  
  e = read(fd, ctx->buf + n, l - n );
  if ( e < 0 && errno != EINTR ) return -1;
  else if ( e > 0 ) n += e;
 }

 return l;
}


static int fdctx_init_with_buf(struct fd_ctx * ctx, char * buf, unsigned int len)
{
 bzero(ctx, sizeof(*ctx));
 ctx->allocated_size = len;
 ctx->buf = buf;
 ctx->ptr = 0;

 return len;
}

/*---------------------------------------------------------------------*/
#define DICTIONNARY_MAGIC 1297
#define DICTIONNARY_EOF   424242
struct dictionnary {
	unsigned int id;
	unsigned int len;
	char * word;
	struct dictionnary * next;
};

static unsigned int dictionnary_hash ( char * word )
{
 unsigned int ret = 0;

 while ( word[0] != '\0' )
	{
	ret += word[0];
	word ++;
	}

 return ret % DICTIONNARY_MAGIC;
}

static struct dictionnary ** dictionnary_init()
{
 return emalloc(sizeof(struct dictionnary *) * DICTIONNARY_MAGIC); 
}

static void dictionnary_free(struct dictionnary ** dict )
{
 int i;
 for ( i = 0 ; i < DICTIONNARY_MAGIC ; i ++ )
 {
  struct dictionnary * d;
  d = dict[i];
  while ( d != NULL )
  {
   struct dictionnary * next;
   efree(&d->word);
   next = d->next;
   efree(&d);
   d = next; 
  }
 }
 efree(&dict);
}


static char * dictionnary_get_word( struct dictionnary ** dict, unsigned int id )
{
 struct dictionnary * d;
 unsigned int h;

 h = id & 0xffff0000;
 h = h >> 16;
 if ( h > DICTIONNARY_MAGIC )
 {
  fprintf(stderr, "Bad dictionnary\n");
  return NULL;
 }

 d = dict[h];
 while ( d != NULL )
 {
  if ( d->id == id ) return d->word;
  d = d->next;
 }
 return NULL;
}


static unsigned int dictionnary_add_word(struct dictionnary ** dict, char * word )
{
 unsigned int h = dictionnary_hash(word);
 struct dictionnary * d;
 unsigned int id;

 d = dict[h];
 while ( d != NULL )
 {
  if ( strcmp(d->word, word) == 0 ) return d->id;
  d = d->next;
 }


 id = h << 16;
 if ( dict[h] != NULL ) id |= ( (dict[h]->id << 16) >> 16 );
 id ++;

 d = emalloc(sizeof(*d));
 d->word = strdup(word);
 d->len  = strlen(word);
 d->id   = id;
 d->next = dict[h];
 dict[h] = d;
 return d->id;
}

static void dictionnary_save ( struct dictionnary ** dict, int fd )
{
 int i;
 unsigned int eof;
 for ( i = 0 ; i < DICTIONNARY_MAGIC ; i ++ )
 {
  struct dictionnary * d = dict[i];
  while ( d != NULL )
  {
   write(fd, &d->id, sizeof(d->id));
   write(fd, &d->len, sizeof(d->len));
   write(fd, d->word, d->len);
   d = d->next;
  }
 }
 
 eof = DICTIONNARY_EOF;
 write(fd, &eof, sizeof(eof));
}


static struct dictionnary ** dictionnary_load( struct fd_ctx * ctx )
{
 struct dictionnary ** ret = dictionnary_init();

 for ( ;; )
 {
  unsigned int l;
  unsigned int id;
  char * word;
  unsigned int h;
  struct dictionnary * d;

  fdctx_read(ctx, &id, sizeof(id));
  if ( id == DICTIONNARY_EOF ) break;

  if ( fdctx_read(ctx, &l, sizeof(l)) < 0 )
	return NULL;

  word = emalloc(l + 1);
  if ( fdctx_read(ctx, word, l) < 0 )
	return NULL;

  h =  id  >> 16;
  if ( h > DICTIONNARY_MAGIC )
  {
   fprintf(stderr, "Badly formed dictionnary file\n"); 
   exit(1);
  }
  d = emalloc( sizeof(struct dictionnary) );
  d->word = word;
  d->id   = id;
  d->len  = l;
  d->next = ret[h];
  ret[h]  = d;
 }

 return ret;
}
/*---------------------------------------------------------------------*/


static int
nasl_saved_parsed_cell(struct fd_ctx * ctx, const tree_cell* tc, struct dictionnary ** dico)
{
  unsigned char	typ;
  int		l, i;
  unsigned char flag;

  if (tc == NULL || tc == FAKE_CELL)
    {
      typ = NODE_EMPTY;
      if (fdctx_write(ctx, &typ, sizeof(typ)) < 0 )
	goto write_error;
      return 0;
    }

  typ = tc->type;
  if (fdctx_write(ctx, &typ, sizeof(typ)) < 0 || 
      fdctx_write(ctx, &tc->line_nb, sizeof(short)) < 0)
    goto write_error;

  switch (typ)
    {
    case CONST_INT:
      if (fdctx_write(ctx, &tc->x.i_val, sizeof(int)) < 0 )
	goto write_error;
      break;

      

    case CONST_STR:
    case CONST_DATA:
    case NODE_VAR:
    case NODE_FUN_DEF:
    case NODE_FUN_CALL:
    case NODE_DECL:
    case NODE_ARG:
    case NODE_ARRAY_EL:
    case NODE_FOREACH:
    case CONST_REGEX:
    case COMP_RE_MATCH:
    case COMP_RE_NOMATCH:
      if (tc->x.str_val != NULL || tc->x.ref_val != NULL)
	{
          char * buf = NULL;
  	  unsigned int id;
	  
          if ( typ == CONST_REGEX ||
               typ == COMP_RE_MATCH ||
               typ == COMP_RE_NOMATCH  ) 
		{
	         if ( tc->x.ref_val != NULL )
                 {
		    buf = nasl_regorig(tc->x.ref_val);
                  }
		}
	   else
		buf = tc->x.str_val;
          
          id = dictionnary_add_word(dico, buf);
	  if ( fdctx_write(ctx, &id, sizeof(id)) < 0 )
	    goto write_error;
	}
      else
	{
	  l = 0;
	  if ( fdctx_write(ctx, &l, sizeof(l) ) < 0 ) 
	    goto write_error;
	}
      break;
    }



  flag = 0;
  for (i = 0; i < 4; i ++)
    {
       if ( tc->link[i] != NULL ) flag = flag | ( 1 << i );
    }

  fdctx_write(ctx, &flag, 1);

  for ( i = 0 ; i < 4 ; i ++ )
    {
     if ( tc->link[i] != NULL )
     {
      if (nasl_saved_parsed_cell(ctx, tc->link[i], dico) < 0)
      return -1;
     }
    }
  return 0;
 write_error:
  perror("fwrite");
  return -1;
}

int
nasl_saved_parsed_tree(const char* fname, const tree_cell* tc)
{
  int fd = open(fname, O_CREAT|O_WRONLY|O_TRUNC, 0644);
  int	err = 0;
  struct fd_ctx ctx;
  struct dictionnary ** dico = dictionnary_init();

  if ( fd < 0 )
  {
   perror(fname);
   return -1;
  }

  if( fdctx_init(&ctx) < 0 ) 
  {
   perror("fdctx_init ");
   return -1;
  }

  if (nasl_saved_parsed_cell(&ctx, tc, dico) < 0)
    err ++;

  dictionnary_save(dico, fd);
  dictionnary_free(dico);
  fdctx_save(&ctx, fd);
  if (close(fd) < 0)
    {
      perror(fname);
      err++;
    }

  fdctx_free(&ctx); 
  return err ? -1 : 0;
}

static int
nasl_load_parsed_cell(struct fd_ctx * ctx, tree_cell** pc, struct dictionnary ** dico, const char * fname)
{
  char*	buf = NULL;
  int	buflen = 0;
  tree_cell	*tc = NULL;
  unsigned char	typ = 0;
  short		line = 0;
  char		*s;
  int		i;
  unsigned 	int 		id;
  unsigned	char		flag;


  
  if (fdctx_read(ctx, &typ, sizeof(typ)) < 0)
  {
    if (fdctx_eof(ctx))
      return 0;
    else
      goto read_error;
  }

  if (typ == NODE_EMPTY)
    {
      *pc = NULL;
      return 0;
    }

  if (fdctx_read(ctx, &line, sizeof(line)) < 0)
    goto read_error;

  tc = alloc_tree_cell(line, NULL);

  switch(typ)
    {
    case CONST_INT:
      if (fdctx_read(ctx, &i, sizeof(i)) < 0)
	goto read_error;
      tc->x.i_val = i;
      break;

    case CONST_STR:
    case CONST_DATA:
    case NODE_VAR:
    case NODE_FUN_DEF:
    case NODE_FUN_CALL:
    case NODE_DECL:
    case NODE_ARG:
    case NODE_ARRAY_EL:
    case NODE_FOREACH:
    case CONST_REGEX:
    case COMP_RE_MATCH:
    case COMP_RE_NOMATCH:
      if ( fdctx_read(ctx, &id, sizeof(id)) < 0 )	goto read_error;
      if ( id != 0 )
      {
       buf = dictionnary_get_word ( dico, id );
       if ( buf == NULL ) goto read_error;
       buflen = strlen(buf);
       s = buf = strdup(buf); 
      }
      else {
	s = NULL;
	buf = NULL;
	buflen = 0;
	}

      tc->x.str_val = buf;
  
      if (typ == CONST_DATA || typ == CONST_STR)
	{
	  tc->size = buflen;
	  if (s == NULL)
		 tc->x.str_val = estrdup("");
	}

      if ( s != NULL && (typ == CONST_REGEX || typ == COMP_RE_MATCH || typ == COMP_RE_NOMATCH ))
	{
	 regex_t * re = emalloc ( sizeof(regex_t) );
         int e;
         
         e = nasl_regcomp(re, s, REG_EXTENDED|REG_NOSUB|REG_ICASE);
         if ( e == 0 ) tc->x.ref_val = re;
         else {
 	  efree (&re);
	  tc->x.ref_val = NULL;
 	  nasl_perror(NULL, "%s:Line %d: Cannot compile regex: %s (error = %d)\n", fname, tc->line_nb, s, e);
	 }
	 efree(&s);
	}

      break;
    }

  tc->type = typ;
  fdctx_read(ctx, &flag, 1);

  for (i = 0; i < 4; i ++)
    {
      if ( flag & ( 1 << i ) )
      { 
       if (nasl_load_parsed_cell(ctx, &tc->link[i], dico, fname) < 0)
       {
	deref_cell(tc);
	return -1;
       }
     }
    }
  *pc = tc;
  return 0;

 read_error:
  perror("fread");
  deref_cell(tc);
  return -1;  
}

tree_cell*
nasl_load_parsed_tree(const char* fname)
{
  tree_cell	*tc = NULL;
  int fd;
  struct fd_ctx ctx;
  struct dictionnary ** dico;

  if ((fd = open(fname, O_RDONLY)) < 0 )
    {
      perror(fname);
      return NULL;
    }

  if ( fdctx_load(&ctx, fd) < 0 )
   {
     perror("fdctx_load ");
     return NULL; 
   }

  dico = dictionnary_load(&ctx);
  if ( dico == NULL ) return NULL;
  close(fd);


  if (nasl_load_parsed_cell(&ctx, &tc, dico, fname) < 0)
    {
      deref_cell(tc);
      tc = NULL;
    }

  dictionnary_free(dico);
  return tc;
}

int
nasl_load_parsed_tree_buf(naslctxt * naslctx, char* buf, unsigned int len, const char * fname)
{
  tree_cell	*tc = NULL;
  struct fd_ctx ctx;
  struct dictionnary ** dico;

  memset(naslctx, 0, sizeof(*naslctx));
 
  if ( fdctx_init_with_buf(&ctx, buf, len) < 0 )
   {
     perror("fdctx_init_with_buf ");
     return -1; 
   }

  dico = dictionnary_load(&ctx);
  if ( dico == NULL ) return -1;

  if (nasl_load_parsed_cell(&ctx, &tc, dico, fname) < 0)
    {
      deref_cell(tc);
      return -1;
    }
 dictionnary_free(dico);
 naslctx->tree = tc;
 return 0; 
}

#endif /* ENABLE_PLUGIN_SERVER */

int
nasl_load_or_parse(naslctxt* ctx, const char* name1, const char * basename, const char * cache_dir)
{
#ifdef ENABLE_PLUGIN_SERVER
  char		name2[MAXPATHLEN];
  struct stat	st1, st2;


  if ( cache_dir != NULL )
  {
   snprintf(name2, sizeof(name2), "%s/%s", cache_dir, basename);
   if (stat(name1, &st1) >= 0 && stat(name2, &st2) >= 0)
   {
    if (st2.st_mtime > st1.st_mtime)
    {
      memset(ctx, 0, sizeof(*ctx));
      if ((ctx->tree = nasl_load_parsed_tree(name2)) != NULL)
	return 0;
    }
   }
  }
#endif

  if (init_nasl_ctx(ctx, name1) < 0)
    return -1;


  if (naslparse(ctx))
    {
      fprintf(stderr, "\nParse error at or near line %d\n", ctx->line_nb);
      nasl_clean_ctx(ctx);
      return -1;
    }
  
#ifdef ENABLE_PLUGIN_SERVER
  if ( cache_dir != NULL )
  {
   if (nasl_saved_parsed_tree(name2, ctx->tree) < 0)
    {
      fprintf(stderr, "Could not dump tree to %s\n", name2);
      if (unlink(name2) < 0)
	perror(name2);
    }
  }
#endif
  return 0;
}


#ifdef ENABLE_PLUGIN_SERVER
int
nasl_parse_and_dump(const char* name1, const char * basename, const char * cache_dir)
{
  char		name2[MAXPATHLEN];
  struct stat	st1, st2;
  naslctxt ctx;

  if ( cache_dir == NULL )  return -1;
  snprintf(name2, sizeof(name2), "%s/%s", cache_dir, basename);


  if (stat(name1, &st1) >= 0 && stat(name2, &st2) >= 0)
  {
    if (st2.st_mtime > st1.st_mtime)
	return 0;
  }

  if (init_nasl_ctx(&ctx, name1) < 0)
    return -1;


  if (naslparse(&ctx))
    {
      fprintf(stderr, "\nParse error at or near line %d\n", ctx.line_nb);
      nasl_clean_ctx(&ctx);
      return -1;
    }
  
  if (nasl_saved_parsed_tree(name2, ctx.tree) < 0)
    {
      fprintf(stderr, "Could not dump tree to %s\n", name2);
      if (unlink(name2) < 0)
	perror(name2);
    }
 
  nasl_clean_ctx(&ctx);
  return 0;
}
#endif
