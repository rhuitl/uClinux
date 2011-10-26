#
# Makefile to build a linux package
#
# Copyright (c) Mbedthis LLC, 2003-2004. All Rights Reserved.
#

include 	make.dep

#
#	Change ku to be sudo or equivalent
#
packageExtra:
	@if [ `id -u` -ne 0 ] ; \
	then \
		echo "Must be root to create a package" ; \
		exit 255 ; \
	fi
	@./makePackage "release binary dev doc samples src"

cleanExtra:
	@rm -fr .pbldtmp rpm.out

## Local variables:
## tab-width: 4
## End:
## vim: tw=78 sw=4 ts=4
