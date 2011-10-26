/* $Id: mkfs.jffs.c,v 1.14 2000/07/18 17:46:27 finn Exp $  */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <linux/types.h>

/*
 *	Set this up to do the correct swapping for your target platform
 */

#if 0
#define	LONG_SWAP(x) x
#define	WORD_SWAP(x) x
#define	BYTE_SWAP(x) x
#else
#define	BYTE_SWAP(x) ((unsigned char) (x))
#define	WORD_SWAP(x) \
		(((unsigned short) BYTE_SWAP((((unsigned short)(x)) & 0xff00) >> 8)) | \
		((unsigned short) (BYTE_SWAP(((unsigned short)(x)) & 0xff) << 8)))
#define	LONG_SWAP(x) \
		(((unsigned int) WORD_SWAP((((unsigned int)(x)) & 0xffff0000) >> 16))|\
		((unsigned int) (WORD_SWAP(((unsigned int)(x)) & 0xffff) << 16)))
#endif

#define BLOCK_SIZE 1024
#define JFFS_MAGIC 0x34383931 /* "1984" */
#define JFFS_MAX_NAME_LEN 256
#define JFFS_MIN_INO 1
#define JFFS_TRACE_INDENT 4
#define JFFS_ALIGN_SIZE 4
#define MAX_CHUNK_SIZE 32768

/* How many padding bytes should be inserted between two chunks of data
   on the flash?  */
#define JFFS_GET_PAD_BYTES(size) ((JFFS_ALIGN_SIZE                     \
				  - ((__u32)(size) % JFFS_ALIGN_SIZE)) \
				  % JFFS_ALIGN_SIZE)


struct jffs_raw_inode
{
  __u32 magic;    /* A constant magic number.  */
  __u32 ino;      /* Inode number.  */
  __u32 pino;     /* Parent's inode number.  */
  __u32 version;  /* Version number.  */
  __u32 mode;     /* file_type, mode  */
  __u16 uid;
  __u16 gid;
  __u32 atime;
  __u32 mtime;
  __u32 ctime;
  __u32 offset;     /* Where to begin to write.  */
  __u32 dsize;      /* Size of the file data.  */
  __u32 rsize;      /* How much are going to be replaced?  */
  __u8 nsize;       /* Name length.  */
  __u8 nlink;       /* Number of links.  */
  __u8 spare : 6;   /* For future use.  */
  __u8 rename : 1;  /* Is this a special rename?  */
  __u8 deleted : 1; /* Has this file been deleted?  */
  __u8 accurate;    /* The inode is obsolete if accurate == 0.  */
  __u32 dchksum;    /* Checksum for the data.  */
  __u16 nchksum;    /* Checksum for the name.  */
  __u16 chksum;     /* Checksum for the raw_inode.  */
};


struct jffs_file
{
  struct jffs_raw_inode inode;
  char *name;
  unsigned char *data;
};

char *root_directory_name;
int fs_pos = 0;
int verbose = 1;

static __u32 jffs_checksum(void *data, int size);
void jffs_print_trace(const char *path, int depth);
int make_root_dir(FILE *fs, int first_ino, const char *root_dir_path,
		  int depth);
void write_file(struct jffs_file *f, FILE *fs, struct stat st);
void read_data(struct jffs_file *f, const char *path, int offset);
int mkfs(FILE *fs, const char *path, int ino, int parent, int depth);


static __u32
jffs_checksum(void *data, int size)
{
  __u32 sum = 0;
  __u8 *ptr = (__u8 *)data;

  while (size-- > 0)
  {
    sum += *ptr++;
  }

  return sum;
}


void jffs_swap_inode(struct jffs_raw_inode *i)
{
  i->magic    = LONG_SWAP(i->magic);
  i->ino      = LONG_SWAP(i->ino);
  i->pino     = LONG_SWAP(i->pino);
  i->version  = LONG_SWAP(i->version);
  i->mode     = LONG_SWAP(i->mode);
  i->uid      = WORD_SWAP(i->uid);
  i->gid      = WORD_SWAP(i->gid);
  i->atime    = LONG_SWAP(i->atime);
  i->mtime    = LONG_SWAP(i->mtime);
  i->ctime    = LONG_SWAP(i->ctime);
  i->offset   = LONG_SWAP(i->offset);
  i->dsize    = LONG_SWAP(i->dsize);
  i->rsize    = LONG_SWAP(i->rsize);
  i->nsize    = BYTE_SWAP(i->nsize);
  i->nlink    = BYTE_SWAP(i->nlink);
#if 0 /* damn bit fields, lucky its a byte */
  i->spare    = BYTE_SWAP(i->spare : 6);
  i->rename   = BYTE_SWAP(i->rename : 1);
  i->deleted  = BYTE_SWAP(i->deleted : 1);
#endif
  i->accurate = BYTE_SWAP(i->accurate);
  i->dchksum  = LONG_SWAP(i->dchksum);
  i->nchksum  = WORD_SWAP(i->nchksum);
  i->chksum   = WORD_SWAP(i->chksum);
}


void
jffs_print_trace(const char *path, int depth)
{
  int path_len = strlen(path);
  int out_pos = depth * JFFS_TRACE_INDENT;
  int pos = path_len - 1;
  char *out = (char *)alloca(depth * JFFS_TRACE_INDENT + path_len + 1);

  if (verbose >= 2)
  {
    fprintf(stderr, "jffs_print_trace(): path: \"%s\"\n", path);
  }

  if (!out) {
    fprintf(stderr, "jffs_print_trace(): Allocation failed.\n");
    fprintf(stderr, " path: \"%s\"\n", path);
    fprintf(stderr, "depth: %d\n", depth);
    exit(1);
  }

  memset(out, ' ', depth * JFFS_TRACE_INDENT);

  if (path[pos] == '/')
  {
    pos--;
  }
  while (path[pos] && (path[pos] != '/'))
  {
    pos--;
  }
  for (pos++; path[pos] && (path[pos] != '/'); pos++)
  {
    out[out_pos++] = path[pos];
  }
  out[out_pos] = '\0';
  fprintf(stderr, "%s\n", out);
}


/* Print the contents of a raw inode.  */
void
jffs_print_raw_inode(struct jffs_raw_inode *raw_inode)
{
	fprintf(stderr, "jffs_raw_inode: inode number: %u\n", raw_inode->ino);
	fprintf(stderr, "{\n");
	fprintf(stderr, "        0x%08x, /* magic  */\n", raw_inode->magic);
	fprintf(stderr, "        0x%08x, /* ino  */\n", raw_inode->ino);
	fprintf(stderr, "        0x%08x, /* pino  */\n", raw_inode->pino);
	fprintf(stderr, "        0x%08x, /* version  */\n", raw_inode->version);
	fprintf(stderr, "        0x%08x, /* mode  */\n", raw_inode->mode);
	fprintf(stderr, "        0x%04x,     /* uid  */\n", raw_inode->uid);
	fprintf(stderr, "        0x%04x,     /* gid  */\n", raw_inode->gid);
	fprintf(stderr, "        0x%08x, /* atime  */\n", raw_inode->atime);
	fprintf(stderr, "        0x%08x, /* mtime  */\n", raw_inode->mtime);
	fprintf(stderr, "        0x%08x, /* ctime  */\n", raw_inode->ctime);
	fprintf(stderr, "        0x%08x, /* offset  */\n", raw_inode->offset);
	fprintf(stderr, "        0x%08x, /* dsize  */\n", raw_inode->dsize);
	fprintf(stderr, "        0x%08x, /* rsize  */\n", raw_inode->rsize);
	fprintf(stderr, "        0x%02x,       /* nsize  */\n", raw_inode->nsize);
	fprintf(stderr, "        0x%02x,       /* nlink  */\n", raw_inode->nlink);
	fprintf(stderr, "        0x%02x,       /* spare  */\n",
		 raw_inode->spare);
	fprintf(stderr, "        %u,          /* rename  */\n",
		 raw_inode->rename);
	fprintf(stderr, "        %u,          /* deleted  */\n",
		 raw_inode->deleted);
	fprintf(stderr, "        0x%02x,       /* accurate  */\n",
		 raw_inode->accurate);
	fprintf(stderr, "        0x%08x, /* dchksum  */\n", raw_inode->dchksum);
	fprintf(stderr, "        0x%04x,     /* nchksum  */\n", raw_inode->nchksum);
	fprintf(stderr, "        0x%04x,     /* chksum  */\n", raw_inode->chksum);
	fprintf(stderr, "}\n");
}


/* This function constructs a root inode with no name and
   no data.  The inode is then written to the filesystem
   image.  */
int
make_root_dir(FILE *fs, int first_ino, const char *root_dir_path, int depth)
{
  struct jffs_file f;
  struct stat st;
  __u16 chksum;

  if (stat(root_dir_path, &st) < 0)
  {
    perror("stat");
    exit(1);
  }

  f.inode.magic = JFFS_MAGIC;
  f.inode.ino = first_ino;
  f.inode.pino = 0;
  f.inode.version = 1;
  f.inode.mode = st.st_mode;
  f.inode.uid = 0; /* root */
  f.inode.gid = 0; /* root */
  f.inode.atime = st.st_atime;
  f.inode.mtime = st.st_mtime;
  f.inode.ctime = st.st_ctime;
  f.inode.offset = 0;
  f.inode.dsize = 0;
  f.inode.rsize = 0;
  f.inode.nsize = 0;
  /*f.inode.nlink = st.st_nlink;*/
  f.inode.nlink = 1;
  f.inode.spare = 0;
  f.inode.rename = 0;
  f.inode.deleted = 0;
  f.inode.accurate = 0;
  f.inode.dchksum = 0;
  f.inode.nchksum = 0;
  f.inode.chksum = 0;
  f.name = 0;
  f.data = 0;
  jffs_swap_inode(&f.inode);
  chksum = jffs_checksum(&f.inode, sizeof(struct jffs_raw_inode));
  jffs_swap_inode(&f.inode);
  f.inode.chksum = chksum;
  f.inode.accurate = 0xff;
  write_file(&f, fs, st);
  if (verbose >= 1)
  {
    jffs_print_trace(root_dir_path, depth);
  }
  if (verbose >= 2)
  {
    jffs_print_raw_inode(&f.inode);
  }
  return first_ino;
}


/* This function writes at least one inode.  */
void
write_file(struct jffs_file *f, FILE *fs, struct stat st)
{
  int npad = JFFS_GET_PAD_BYTES(f->inode.nsize);
  int dpad = JFFS_GET_PAD_BYTES(f->inode.dsize);
  int size = sizeof(struct jffs_raw_inode) + f->inode.nsize + npad
             + f->inode.dsize + dpad;
  unsigned char ff_data[] = { 0xff, 0xff, 0xff, 0xff };

  if (verbose >= 2)
  {
    fprintf(stderr, "***write_file()\n");
  }
  jffs_swap_inode(&f->inode);
  fwrite((void *)&f->inode, sizeof(struct jffs_raw_inode), 1, fs);
  jffs_swap_inode(&f->inode);
  if (f->inode.nsize)
  {
    fwrite(f->name, 1, f->inode.nsize, fs);
    if (npad)
    {
      fwrite(ff_data, 1, npad, fs);
    }
  }

  if (f->inode.dsize)
  {
    if (S_ISBLK(st.st_mode) || S_ISCHR(st.st_mode))
    {
	  if (sizeof(st.st_rdev) == 2)
	    st.st_rdev = WORD_SWAP(st.st_rdev);
	  else if (sizeof(st.st_rdev) == 4)
	    st.st_rdev = LONG_SWAP(st.st_rdev);
      fwrite((char *)&st.st_rdev, sizeof(st.st_rdev)/4, 1, fs);
	  if (sizeof(st.st_rdev) == 2)
	    st.st_rdev = WORD_SWAP(st.st_rdev);
	  else if (sizeof(st.st_rdev) == 4)
	    st.st_rdev = LONG_SWAP(st.st_rdev);
    }
    else
    {
      fwrite(f->data, 1, f->inode.dsize, fs);
    }
    if (dpad)
    {
      fwrite(ff_data, 1, dpad, fs);
    }
  }

  fs_pos += size;
  /* If the space left on the block is smaller than the size of an
     inode, then skip it.  */
}


void
read_data(struct jffs_file *f, const char *path, int offset)
{
  FILE *file;
  char *tot_path;
  int pos = 0;
  int r;

  if (verbose >= 2)
  {
    fprintf(stderr, "***read_data(): f: 0x%08x, path: \"%s\", offset: %u\r\n",
            (unsigned int)f, path, offset);
    fprintf(stderr, "             file's size: %u\n", f->inode.dsize);
  }

  if (!(f->data = (unsigned char *)malloc(f->inode.dsize)))
  {
    fprintf(stderr, "read_data(): malloc() failed! (*data)\n");
    exit(1);
  }

  if (!(tot_path = (char *)alloca(strlen(path) + f->inode.nsize + 1)))
  {
    fprintf(stderr, "read_data(): alloca() failed! (tot_path)\n");
    exit(1);
  }
  strcpy(tot_path, path);
  strncat(tot_path, f->name, f->inode.nsize);

  if (!(file = fopen(tot_path, "r")))
  {
    fprintf(stderr, "read_data(): Couldn't open \"%s\".\n", tot_path);
    exit(1);
  }

  if (fseek(file, offset, SEEK_SET) < 0)
  {
    fprintf(stderr, "read_data(): fseek failure: path = %s, offset = %u.\n",
            path, offset);
    exit(1);
  }

  while (pos < f->inode.dsize)
  {
    if ((r = fread(&f->data[pos], 1, f->inode.dsize - pos, file)) < 0)
    {
      fprintf(stderr, "read_data(): fread failure (%s).\n", path);
      exit(1);
    }
    pos += r;
  }

  fclose(file);
}


/* This is the routine that constructs the filesystem image.  */
int
mkfs(FILE *fs, const char *path, int ino, int parent, int depth)
{
  struct dirent *dir_entry;
  DIR *dir;
  struct stat st;
  struct jffs_file f;
  int name_len;
  int pos = 0;
  int new_ino = ino;
  char *filename;
  int path_len = strlen(path);
  __u16 chksum;

  if (verbose >= 2)
  {
    fprintf(stderr, "***mkfs(): path: \"%s\"\r\n", path);
  }

  if (!(dir = opendir(path)))
  {
    perror("opendir");
    fprintf(stderr, "mkfs(): opendir() failed! (%s)\n", path);
    exit(1);
  }

  while ((dir_entry = readdir(dir)))
  {
    if (verbose >= 2)
    {
     fprintf(stderr, "mkfs(): name: %s\n", dir_entry->d_name);
    }
    name_len = strlen(dir_entry->d_name);

    if (((name_len == 1)
         && (dir_entry->d_name[0] == '.'))
        || ((name_len == 2)
            && (dir_entry->d_name[0] == '.')
            && (dir_entry->d_name[1] == '.')))
    {
      continue;
    }

    if (!(filename = (char *)alloca(path_len + name_len + 1)))
    {
      fprintf(stderr, "mkfs(): Allocation failed!\n");
      exit(0);
    }
    strcpy(filename, path);
    strcat(filename, dir_entry->d_name);

    if (verbose >= 2)
    {
      fprintf(stderr, "mkfs(): filename: %s\n", filename);
    }

    if (lstat(filename, &st) < 0)
    {
      perror("lstat");
      exit(1);
    }

    if (verbose >= 2)
    {
      fprintf(stderr, "mkfs(): filename: \"%s\", ino: %d, parent: %d\n",
              filename, new_ino, parent);
    }

    f.inode.magic = JFFS_MAGIC;
    f.inode.ino = new_ino;
    f.inode.pino = parent;
    f.inode.version = 1;
    f.inode.mode = st.st_mode;
    f.inode.uid = st.st_uid;
    f.inode.gid = st.st_gid;
    f.inode.atime = st.st_atime;
    f.inode.mtime = st.st_mtime;
    f.inode.ctime = st.st_ctime;
    f.inode.dsize = 0;
    f.inode.rsize = 0;
    f.inode.nsize = name_len;
    /*f.inode.nlink = st.st_nlink;*/
    f.inode.nlink = 1;
    f.inode.spare = 0;
    f.inode.rename = 0;
    f.inode.deleted = 0;
    f.inode.accurate = 0;
    f.inode.dchksum = 0;
    f.inode.nchksum = 0;
    f.inode.chksum = 0;
    if (dir_entry->d_name)
    {
      f.name = strdup(dir_entry->d_name);
    }
    else
    {
      f.name = 0;
    }

  repeat:
    f.inode.offset = pos;
    f.data = 0;
    f.inode.accurate = 0;
    if (S_ISREG(st.st_mode) && st.st_size)
    {
      if (st.st_size - pos < MAX_CHUNK_SIZE)
      {
	f.inode.dsize = st.st_size - pos;
      }
      else
      {
	f.inode.dsize = MAX_CHUNK_SIZE;
      }

      read_data(&f, path, pos);
      pos += f.inode.dsize;
    }
    else if (S_ISLNK(st.st_mode))
    {
      int linklen;
      unsigned char *linkdata = (unsigned char *)malloc(1000);
      if (!linkdata)
      {
        fprintf(stderr, "mkfs(): malloc() failed! (linkdata)\n");
        exit(1);
      }
      if ((linklen = readlink(filename, linkdata, 1000)) < 0)
      {
        free(linkdata);
        fprintf(stderr, "mkfs(): readlink() failed! f.name = \"%s\"\n",
                f.name);
        exit(1);
      }

      f.inode.dsize = linklen;
      f.data = linkdata;
      f.data[linklen] = '\0';
    }
    else if (S_ISBLK(st.st_mode) || S_ISCHR(st.st_mode))
    {
      f.inode.dsize = sizeof(st.st_rdev) / 4;
    }

    f.inode.chksum = 0;
    if (!S_ISBLK(st.st_mode) && !S_ISCHR(st.st_mode))
    {
      f.inode.dchksum = jffs_checksum((void *)f.data, f.inode.dsize);
    }
    else
    {
      f.inode.dchksum
	= jffs_checksum((void *)&st.st_rdev, sizeof(st.st_rdev) / 4);
    }

    f.inode.nchksum = jffs_checksum((void *)f.name, f.inode.nsize);
	jffs_swap_inode(&f.inode);
    chksum = jffs_checksum((void *)&f.inode, sizeof(struct jffs_raw_inode));
	jffs_swap_inode(&f.inode);
    f.inode.chksum = chksum;
    f.inode.accurate = 0xff;

    write_file(&f, fs, st);
    if (S_ISREG(st.st_mode) && st.st_size)
    {
      if (pos < st.st_size)
      {
	f.inode.version++;
	goto repeat;
      }
    }

    new_ino++;
    pos = 0;
    if (verbose >= 1)
    {
      jffs_print_trace(f.name, depth);
    }
    if (verbose >= 2)
    {
      jffs_print_raw_inode(&f.inode);
    }

    if (S_ISDIR(st.st_mode))
    {
      char *new_path;

      if (!(new_path = (char *)alloca(strlen(path) + name_len + 1 + 1)))
      {
        fprintf(stderr, "mkfs(): alloca() failed! (new_path)\n");
        exit(1);
      }
      strcpy(new_path, path);
      strncat(new_path, f.name, f.inode.nsize);
      strcat(new_path, "/");

      if (verbose >= 2)
      {
        fprintf(stderr, "mkfs(): new_path: \"%s\"\n", new_path);
      }
      new_ino = mkfs(fs, new_path, new_ino, new_ino - 1, depth + 1);
    }
    if (f.name)
    {
      free(f.name);
    }
    if (f.data)
    {
      free(f.data);
    }
  }

  closedir(dir);
  return new_ino;
}


void
usage(void)
{
  fprintf(stderr, "Usage: mkfs.jffs -d root_directory\n");
}


int
main(int argc, char **argv)
{
  FILE *fs;
  int root_ino;
  int len;

  switch (argc)
  {
  case 1:
    fprintf(stderr, "Too few arguments!\n");
    usage();
    exit(0);
  case 2:
    if ((strlen(argv[1]) <= 2) || (argv[1][0] != '-'))
    {
      usage();
      exit(0);
    }
    if (argv[1][1] == 'd')
    {
      len = strlen(&argv[1][2]);
      root_directory_name = (char *)malloc(len + 2);
      memcpy(root_directory_name, &argv[1][2], len);
      if (root_directory_name[len - 1] != '/')
      {
        root_directory_name[len++] = '/';
      }
      root_directory_name[len] = '\0';
    }
    else
    {
      fprintf(stderr, "Invalid option -- %c\n", argv[1][1]);
      usage();
      exit(0);
    }
    break;
  case 3:
    if ((strlen(argv[1]) != 2) || (argv[1][0] != '-'))
    {
      usage();
      exit(0);
    }
    if (argv[1][1] != 'd')
    {
      fprintf(stderr, "Invalid option -- %c\n", argv[1][1]);
      usage();
      exit(0);
    }
    len = strlen(argv[2]);
    root_directory_name = (char *)malloc(len + 2);
    memcpy(root_directory_name, argv[2], len);
    if (root_directory_name[len - 1] != '/')
    {
      root_directory_name[len++] = '/';
    }
    root_directory_name[len] = '\0';
    break;
  default:
    fprintf(stderr, "Too many arguments!\n");
    usage();
    exit(0);
    break;
  }

  fs = stdout; /* For now...  */

  if (verbose >= 1)
  {
    fprintf(stderr, "Constructing JFFS filesystem...\n");
  }
  root_ino = make_root_dir(fs, JFFS_MIN_INO, root_directory_name, 0);
  mkfs(fs, root_directory_name, root_ino + 1, root_ino, 1);

  fclose(fs);
  free(root_directory_name);
  exit(0);
}
