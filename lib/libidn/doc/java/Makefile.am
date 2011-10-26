## Process this file with automake to produce Makefile.in
# Copyright (C) 2004 Simon Josefsson.
#
# This file is part of GNU Libidn.
#
# GNU Libidn is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 2.1 of
# the License, or (at your option) any later version.
#
# GNU Libidn is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with GNU Libidn; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA

if JAVA
HTML = AllNames.html packages.html tree.html			\
	gnu.inet.encoding.PunycodeException.html		\
	gnu.inet.encoding.CombiningClass.html			\
	gnu.inet.encoding.Punycode.html				\
	gnu.inet.encoding.Composition.html			\
	gnu.inet.encoding.RFC3454.html				\
	gnu.inet.encoding.DecompositionKeys.html		\
	gnu.inet.encoding.StringprepException.html		\
	gnu.inet.encoding.DecompositionMappings.html		\
	gnu.inet.encoding.Stringprep.html			\
	gnu.inet.encoding.IDNAException.html			\
	gnu.inet.encoding.IDNA.html gnu.inet.encoding.NFKC.html
EXTRA_DIST = $(HTML)

all:
	cd ../../java && make javadoc

clean-local:
	rm -f $(HTML)
endif
