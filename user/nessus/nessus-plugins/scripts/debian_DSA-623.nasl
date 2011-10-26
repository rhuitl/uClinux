# This script was automatically generated from the dsa-623
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Jonathan Rockway discovered a buffer overflow in nasm, the
general-purpose x86 assembler, which could lead to the execution of
arbitrary code when compiling a maliciously crafted assembler source
file.
For the stable distribution (woody) this problem has been fixed in
version 0.98.28cvs-1woody2.
For the unstable distribution (sid) this problem has been fixed in
version 0.98.38-1.1.
We recommend that you upgrade your nasm package.


Solution : http://www.debian.org/security/2005/dsa-623
Risk factor : High';

if (description) {
 script_id(16096);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "623");
 script_cve_id("CVE-2004-1287");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA623] DSA-623-1 nasm");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-623-1 nasm");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'nasm', release: '3.0', reference: '0.98.28cvs-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nasm is vulnerable in Debian 3.0.\nUpgrade to nasm_0.98.28cvs-1woody2\n');
}
if (deb_check(prefix: 'nasm', release: '3.1', reference: '0.98.38-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nasm is vulnerable in Debian 3.1.\nUpgrade to nasm_0.98.38-1.1\n');
}
if (deb_check(prefix: 'nasm', release: '3.0', reference: '0.98.28cvs-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nasm is vulnerable in Debian woody.\nUpgrade to nasm_0.98.28cvs-1woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
