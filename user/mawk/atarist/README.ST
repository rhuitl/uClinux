The following worked for mawk1.1.x.
It has not been updated for mawk1.2(beta)
-------------------------------------------------------------

This is a quick mawk port to the atariST/StE/TT using
gcc + libs @ Patchlevel 73

Compiling:
  if you are cross compiling issue:
	build_mawk atarist

  if you are native compiling issue:
	gnumake CC=gcc CFLAGS=-O RANLIB= AR=gcc-ar MATHLIB=-lpml

Testing:
   use the gulam scripts mawktest.g and fpe_test.g in the test directory.
   Make sure you pick up cmp or diff from the gnu stuff 
   on atari.archive to run the test scripts.

report atari related problems to:
--
bang:   uunet!cadence!bammi			jwahar r. bammi
domain: bammi@cadence.com
GEnie:	J.Bammi
CIS:    71515,155
