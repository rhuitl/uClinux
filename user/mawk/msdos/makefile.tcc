
#  this is a makefile for mawk under DOS
#  with Borland make
#
#   make    --  mawk.exe

#  for a unix style command line add
#  -DREARV=your_reargv_file without the extension
#
#  e.g. -DREARGV=argvmks

#$Log: makefile.tcc,v $
# Revision 1.1  1995/08/20  17:44:37  mike
# minor fixes to msc and lower case makefile names
#
# Revision 1.3  1995/01/08  22:56:34  mike
# minor tweaks
#
# Revision 1.2  1995/01/07  21:16:03  mike
# remove small model
#

.SWAP

# user settable
# change here or override from command line e.g. -DCC=bcc

TARGET=mawk

!if ! $d(CC)
CC=tcc   # bcc or ?
!endif

!if ! $d(LIBDIR)
LIBDIR =c:\lib    # where are your Borland C libraries ?
!endif

!if !  $d(FLOATLIB)
FLOATLIB=emu   #  or  fp87 if you have fp87 hardware
!endif

!if ! $d(WILDCARD)
WILDCARD=$(LIBDIR)\wildargs.obj
!endif

# compiler flags
# -G optimize for speed
# -d merge duplicate strings
# -v- symbolic debugging off
# -O  optimize
# -ml  large model
CFLAGS = -ml -c -d -v- -O -G

LFLAGS = /c  #case sensitive linking

# how to delete a file
!if ! $d(RM)
RM = del    # rm
!endif

# how to rename a file
!if ! $d(RENAME)
RENAME = rename  # mv
!endif

!if ! $d(COPY)
COPY = copy  # cp
!endif

##############################
# end of user settable
#

MODEL=l

CFLAGS=-m$(MODEL) $(CFLAGS)

!if  $d(REARGV)
CFLAGS=$(CFLAGS) -DHAVE_REARGV=1 
!endif

OBS = parse.obj \
array.obj \
bi_funct.obj \
bi_vars.obj \
cast.obj \
code.obj \
da.obj \
error.obj \
execute.obj \
fcall.obj \
field.obj \
files.obj \
fin.obj \
hash.obj \
init.obj \
jmp.obj \
kw.obj \
main.obj \
matherr.obj \
memory.obj \
missing.obj \
print.obj \
re_cmpl.obj \
scan.obj \
scancode.obj \
split.obj \
zmalloc.obj  \
version.obj  \
dosexec.obj

!if  $d(REARGV)
OBS = $(OBS) $(REARGV).obj
!endif

REXP_OBS = rexp.obj \
rexp0.obj \
rexp1.obj \
rexp2.obj \
rexp3.obj

LIBS = $(LIBDIR)\$(FLOATLIB) \
$(LIBDIR)\math$(MODEL) $(LIBDIR)\c$(MODEL)

$(TARGET).exe : $(OBS)  $(REXP_OBS)
	tlink $(LFLAGS) @&&!
	$(LIBDIR)\c0$(MODEL) $(WILDCARD) $(OBS) $(REXP_OBS)
	$(TARGET),$(TARGET)
	$(LIBS)
!

.c.obj :
	$(CC) $(CFLAGS) {$*.c }


config.h : msdos\tcc.h
	$(COPY) msdos\tcc.h config.h

dosexec.c : msdos\dosexec.c
	$(COPY) msdos\dosexec.c dosexec.c

#scancode.c :  makescan.c  scan.h
#	$(CC) makescan.c
#	makescan.exe > scancode.c
#	$(RM) makescan.obj
#	$(RM) makescan.exe


###################################################
# parse.c is provided 
# so you don't need to make it.
#
# But if you do:  here's how:
# To make it with bison under msdos
# YACC=bison -y
# parse.c : parse.y 
#	$(YACC) -d parse.y
#	$(RENAME) y_tab.h parse.h
#	$(RENAME) y_tab.c parse.c
########################################


clean  :
	$(RM)  *.obj

distclean :
	$(RM) *.obj
	$(RM) config.h dosexec.c
	$(RM) mawk.exe

RFLAGS=-Irexp -DMAWK

rexp.obj  :  rexp\rexp.c  rexp\rexp.h
	$(CC) $(CFLAGS) $(RFLAGS) rexp\rexp.c

rexp0.obj  :  rexp\rexp0.c  rexp\rexp.h
	$(CC) $(CFLAGS) $(RFLAGS) rexp\rexp0.c

rexp1.obj  :  rexp\rexp1.c  rexp\rexp.h
	$(CC) $(CFLAGS) $(RFLAGS) rexp\rexp1.c

rexp2.obj  :  rexp\rexp2.c  rexp\rexp.h
	$(CC) $(CFLAGS) $(RFLAGS) rexp\rexp2.c

rexp3.obj  :  rexp\rexp3.c  rexp\rexp.h
	$(CC) $(CFLAGS) $(RFLAGS) rexp\rexp3.c


#  dependencies of .objs on .h
array.obj : config.h field.h bi_vars.h mawk.h symtype.h nstd.h memory.h zmalloc.h types.h sizes.h
bi_funct.obj : config.h field.h bi_vars.h mawk.h init.h regexp.h symtype.h nstd.h repl.h memory.h bi_funct.h files.h zmalloc.h fin.h types.h sizes.h
bi_vars.obj : config.h field.h bi_vars.h mawk.h init.h symtype.h nstd.h memory.h zmalloc.h types.h sizes.h
cast.obj : config.h field.h mawk.h parse.h symtype.h nstd.h memory.h repl.h scan.h zmalloc.h types.h sizes.h
code.obj : config.h field.h code.h mawk.h init.h symtype.h nstd.h memory.h jmp.h zmalloc.h types.h sizes.h
da.obj : config.h field.h code.h mawk.h symtype.h nstd.h memory.h repl.h bi_funct.h zmalloc.h types.h sizes.h
error.obj : config.h bi_vars.h mawk.h parse.h vargs.h symtype.h nstd.h scan.h types.h sizes.h
execute.obj : config.h field.h bi_vars.h code.h mawk.h regexp.h symtype.h nstd.h memory.h repl.h bi_funct.h zmalloc.h types.h fin.h sizes.h
fcall.obj : config.h code.h mawk.h symtype.h nstd.h memory.h zmalloc.h types.h sizes.h
field.obj : config.h field.h bi_vars.h mawk.h init.h parse.h regexp.h symtype.h nstd.h memory.h repl.h scan.h zmalloc.h types.h sizes.h
files.obj : config.h mawk.h nstd.h memory.h files.h zmalloc.h types.h fin.h sizes.h
fin.obj : config.h field.h bi_vars.h mawk.h parse.h symtype.h nstd.h memory.h scan.h zmalloc.h types.h fin.h sizes.h
hash.obj : config.h mawk.h symtype.h nstd.h memory.h zmalloc.h types.h sizes.h
init.obj : config.h field.h bi_vars.h code.h mawk.h init.h symtype.h nstd.h memory.h zmalloc.h types.h sizes.h
jmp.obj : config.h code.h mawk.h init.h symtype.h nstd.h memory.h jmp.h zmalloc.h types.h sizes.h
kw.obj : config.h mawk.h init.h parse.h symtype.h nstd.h types.h sizes.h
main.obj : config.h field.h bi_vars.h code.h mawk.h init.h symtype.h nstd.h memory.h files.h zmalloc.h types.h fin.h sizes.h
makescan.obj : parse.h symtype.h scan.h
matherr.obj : config.h mawk.h nstd.h types.h sizes.h
memory.obj : config.h mawk.h nstd.h memory.h zmalloc.h types.h sizes.h
missing.obj : config.h nstd.h
parse.obj : config.h field.h bi_vars.h code.h mawk.h symtype.h nstd.h memory.h bi_funct.h files.h zmalloc.h jmp.h types.h sizes.h
print.obj : config.h field.h bi_vars.h mawk.h parse.h symtype.h nstd.h memory.h scan.h bi_funct.h files.h zmalloc.h types.h sizes.h
re_cmpl.obj : config.h mawk.h parse.h regexp.h symtype.h nstd.h memory.h repl.h scan.h zmalloc.h types.h sizes.h
scan.obj : config.h field.h code.h mawk.h init.h parse.h symtype.h nstd.h memory.h repl.h scan.h files.h zmalloc.h types.h fin.h sizes.h
split.obj : config.h field.h bi_vars.h mawk.h parse.h regexp.h symtype.h nstd.h memory.h scan.h bi_funct.h zmalloc.h types.h sizes.h
version.obj : config.h mawk.h patchlev.h nstd.h types.h sizes.h
zmalloc.obj : config.h mawk.h nstd.h zmalloc.h types.h sizes.h
