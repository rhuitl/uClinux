##
## qc-a60.mak:						aug '90
##
## Erik Schoenfelder (schoenfr@tubsibr.uucp)
##
## Makefile for a60 (MSDOS with Quick-C v2.0)
##

PROJ	= A60
DEBUG	= 0
CC	= qcl
CFLAGS_G	= /AL /W1 /Za /DMSDOS
CFLAGS_D	= /Zd /Zr /Od
CFLAGS_R	= /O /Ol /DNDEBUG
CFLAGS	=$(CFLAGS_G) $(CFLAGS_R)
LFLAGS_G	= /CP:0xffff /NOI /SE:0x80 /ST:0x8a00
LFLAGS_D	= /INCR
LFLAGS_R	=
LFLAGS	=$(LFLAGS_G) $(LFLAGS_R)
RUNFLAGS	=
OBJS_EXT = 	
LIBS_EXT = 	

all:	$(PROJ).exe

main.obj:	main.c

a60-ptab.obj:	a60-ptab.c

a60-scan.obj:	a60-scan.c

check.obj:	check.c

stmt.obj:	stmt.c

symtab.obj:	symtab.c

tree.obj:	tree.c

type.obj:	type.c

util.obj:	util.c

run.obj:	run.c

expr.obj:	expr.c

eval.obj:	eval.c

doeval.obj:     doeval.c

bltin.obj:	bltin.c

err.obj:	err.c

mkc.obj:	mkc.c

$(PROJ).exe:	main.obj a60-ptab.obj a60-scan.obj check.obj stmt.obj symtab.obj \
	 tree.obj type.obj util.obj run.obj expr.obj eval.obj doeval.obj bltin.obj \
	err.obj mkc.obj $(OBJS_EXT)
	echo >NUL @<<$(PROJ).crf
main.obj +
a60-ptab.obj +
a60-scan.obj +
check.obj +
stmt.obj +
symtab.obj +
tree.obj +
type.obj +
util.obj +
run.obj +
expr.obj +
eval.obj +
doeval.obj +
bltin.obj +
err.obj +
mkc.obj +
$(OBJS_EXT)
$(PROJ).exe

$(LIBS_EXT);
<<
	link $(LFLAGS) @$(PROJ).crf

run: $(PROJ).exe
	$(PROJ) $(RUNFLAGS)
