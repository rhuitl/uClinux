# tinylogin/docs/Makefile - Create the documentation
# ------------------------
# Copyright (C) 2000  Erik Andersen <andersee@debian.org>  GPL

all:: clean doc

doc:
	@echo
	@echo TinyLogin Documentation
	@echo
	pod2html tinylogin.pod > ../TinyLogin.html 
	@rm pod2html-*
	pod2man --center=TinyLogin --release="version $(VERSION)" tinylogin.pod > ../TinyLogin.1
	pod2text tinylogin.pod > ../TinyLogin.txt

clean::
	@rm -f ../TinyLogin.html ../TinyLogin.1 ../TinyLogin.txt pod2html*

distclean: clean

.PHONY: all clean distclean doc

