#
# Makefile
#
# Make file for simple sample application for the Open H323 library.
#
# Copyright (c) 1998-2000 Equivalence Pty. Ltd.
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
# The Original Code is Open H323 Library.
#
# The Initial Developer of the Original Code is Equivalence Pty. Ltd.
#
# Contributor(s): ______________________________________.
#
# $Log: Makefile,v $
# Revision 1.4  2002/07/19 01:51:41  robertj
# Fixed up directory defaults for openh323 directory.
#
# Revision 1.3  2002/02/11 06:20:07  robertj
# Moved version.h to root directory so have one for the library and not just
#   the sample application. SimpH323 uses the library version so they remain
#   in sync.
#
# Revision 1.2  2000/10/30 00:24:49  robertj
# No longer need to include ptlib explicitly
#
# Revision 1.1  2000/05/11 04:05:57  robertj
# Simple sample program.
#

PROG		= simph323
SOURCES		:= main.cxx

ifndef OPENH323DIR
OPENH323DIR=$(CURDIR)/../..
endif

VERSION_FILE := $(OPENH323DIR)/version.h

include $(OPENH323DIR)/openh323u.mak

