# This script was automatically generated from the dsa-097
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Patrice Fournier discovered a bug in all versions of Exim older than
Exim 3.34 and Exim 3.952.
The Exim maintainer, Philip Hazel,
writes about this issue: "The
problem exists only in the case of a run time configuration which
directs or routes an address to a pipe transport without checking the
local part of the address in any way.  This does not apply, for
example, to pipes run from alias or forward files, because the local
part is checked to ensure that it is the name of an alias or of a
local user.  The bug\'s effect is that, instead of obeying the correct
pipe command, a broken Exim runs the command encoded in the local part
of the address."
This problem has been fixed in Exim version 3.12-10.2 for the stable
distribution Debian GNU/Linux 2.2 and 3.33-1.1 for the testing and
unstable distribution.  We recommend that you upgrade your exim
package.


Solution : http://www.debian.org/security/2002/dsa-097
Risk factor : High';

if (description) {
 script_id(14934);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "097");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA097] DSA-097-1 exim");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-097-1 exim");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'exim', release: '2.2', reference: '3.12-10.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package exim is vulnerable in Debian 2.2.\nUpgrade to exim_3.12-10.2\n');
}
if (deb_check(prefix: 'eximon', release: '2.2', reference: '3.12-10.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package eximon is vulnerable in Debian 2.2.\nUpgrade to eximon_3.12-10.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
