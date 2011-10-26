#
# pwlib.mak
#
# mak rules to be included in a pwlib application Makefile.
#
# Portable Windows Library
#
# Copyright (c) 1993-1998 Equivalence Pty. Ltd.
#
# The contents of this file are subject to the Mozilla Public License
# Version 1.0 (the "License"); you may not use this file except in
# compliance with the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/
#
# Software distributed under the License is distributed on an "AS IS"
# basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
# the License for the specific language governing rights and limitations
# under the License.
#
# The Original Code is Portable Windows Library.
#
# The Initial Developer of the Original Code is Equivalence Pty. Ltd.
#
# Portions are Copyright (C) 1993 Free Software Foundation, Inc.
# All Rights Reserved.
# 
# Contributor(s): ______________________________________.
#
# $Log: pwlib.mak,v $
# Revision 1.5  2005/02/23 21:29:52  dominance
# have configure check for bison as we know we'll need it and stop implicit definition of PWLIBDIR. *geesh* that was about time, eh? ;)
#
# Revision 1.4  1998/12/02 02:39:53  robertj
# New directory structure.
#
# Revision 1.2  1998/11/26 07:29:23  craigs
# *** empty log message ***
#
# Revision 1.1  1998/11/22 10:42:29  craigs
# Initial revision
#
# Revision 1.3  1998/10/16 13:45:17  robertj
# Fixed included make file name
#
# Revision 1.2  1998/09/24 04:20:53  robertj
# Added open software license.
#

ifndef PWLIBDIR
	echo "No PWLIBDIR environment variable defined!"
	echo "You need to define PWLIBDIR!"
	echo "Try something like:"
	echo "PWLIBDIR = $(HOME)/pwlib"
	exit 1
endif

include $(PWLIBDIR)/make/unix.mak
include $(PWLIBDIR)/make/gui.mak
include $(PWLIBDIR)/make/common.mak

# End of pwlib.mak
