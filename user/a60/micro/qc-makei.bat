rem making a60.exe:
	qcl /AL /W1 /Za /DMSDOS /DNDEBUG -c a60-ptab.c
	qcl /AL /W1 /Za /DMSDOS /O /Ol /DNDEBUG -c a60-scan.c
	qcl /AL /W1 /Za /DMSDOS /O /Ol /DNDEBUG -c main.c
	qcl /AL /W1 /Za /DMSDOS /O /Ol /DNDEBUG -c check.c
	qcl /AL /W1 /Za /DMSDOS /O /Ol /DNDEBUG -c stmt.c
	qcl /AL /W1 /Za /DMSDOS /O /Ol /DNDEBUG -c symtab.c
	qcl /AL /W1 /Za /DMSDOS /O /Ol /DNDEBUG -c tree.c
	qcl /AL /W1 /Za /DMSDOS /O /Ol /DNDEBUG -c type.c
	qcl /AL /W1 /Za /DMSDOS /O /Ol /DNDEBUG -c util.c
	qcl /AL /W1 /Za /DMSDOS /O /Ol /DNDEBUG -c run.c
	qcl /AL /W1 /Za /DMSDOS /O /Ol /DNDEBUG -c expr.c
	qcl /AL /W1 /Za /DMSDOS /O /Ol /DNDEBUG -c eval.c
	qcl /AL /W1 /Za /DMSDOS /O /Ol /DNDEBUG -c doeval.c
	qcl /AL /W1 /Za /DMSDOS /O /Ol /DNDEBUG -c bltin.c
	qcl /AL /W1 /Za /DMSDOS /O /Ol /DNDEBUG -c err.c
	qcl /AL /W1 /Za /DMSDOS /O /Ol /DNDEBUG -c mkc.c
	nmake -f qc-a60.mak
