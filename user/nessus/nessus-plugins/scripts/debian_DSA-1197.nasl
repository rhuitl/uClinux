# This script was automatically generated from the dsa-1197
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Benjamin C. Wiley Sittler discovered that the repr() of the Python 
interpreter allocates insufficient memory when parsing UCS-4 Unicode
strings, which might lead to execution of arbitrary code through
a buffer overflow.
For the stable distribution (sarge) this problem has been fixed in
version 2.4.1-2sarge1. Due to build problems this update lacks fixed
packages for the m68k architecture. Once they are sorted out, binaries
for m68k will be released.
For the unstable distribution (sid) this problem has been fixed in
version 2.4.4-1.
We recommend that you upgrade your Python 2.4 packages.


Solution : http://www.debian.org/security/2006/dsa-1197
Risk factor : High';

if (description) {
 script_id(22906);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1197");
 script_cve_id("CVE-2006-4980");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1197] DSA-1197-1 python2.4");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1197-1 python2.4");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'python2.4', release: '', reference: '2.4.4-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.4 is vulnerable in Debian .\nUpgrade to python2.4_2.4.4-1\n');
}
if (deb_check(prefix: 'idle-python2.4', release: '3.1', reference: '2.4.1-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package idle-python2.4 is vulnerable in Debian 3.1.\nUpgrade to idle-python2.4_2.4.1-2sarge1\n');
}
if (deb_check(prefix: 'python2.4', release: '3.1', reference: '2.4.1-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.4 is vulnerable in Debian 3.1.\nUpgrade to python2.4_2.4.1-2sarge1\n');
}
if (deb_check(prefix: 'python2.4-dbg', release: '3.1', reference: '2.4.1-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.4-dbg is vulnerable in Debian 3.1.\nUpgrade to python2.4-dbg_2.4.1-2sarge1\n');
}
if (deb_check(prefix: 'python2.4-dev', release: '3.1', reference: '2.4.1-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.4-dev is vulnerable in Debian 3.1.\nUpgrade to python2.4-dev_2.4.1-2sarge1\n');
}
if (deb_check(prefix: 'python2.4-doc', release: '3.1', reference: '2.4.1-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.4-doc is vulnerable in Debian 3.1.\nUpgrade to python2.4-doc_2.4.1-2sarge1\n');
}
if (deb_check(prefix: 'python2.4-examples', release: '3.1', reference: '2.4.1-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.4-examples is vulnerable in Debian 3.1.\nUpgrade to python2.4-examples_2.4.1-2sarge1\n');
}
if (deb_check(prefix: 'python2.4-gdbm', release: '3.1', reference: '2.4.1-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.4-gdbm is vulnerable in Debian 3.1.\nUpgrade to python2.4-gdbm_2.4.1-2sarge1\n');
}
if (deb_check(prefix: 'python2.4-tk', release: '3.1', reference: '2.4.1-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.4-tk is vulnerable in Debian 3.1.\nUpgrade to python2.4-tk_2.4.1-2sarge1\n');
}
if (deb_check(prefix: 'python2.4', release: '3.1', reference: '2.4.1-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.4 is vulnerable in Debian sarge.\nUpgrade to python2.4_2.4.1-2sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
