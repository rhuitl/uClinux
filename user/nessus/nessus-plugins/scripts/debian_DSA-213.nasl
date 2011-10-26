# This script was automatically generated from the dsa-213
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Glenn Randers-Pehrson discovered a problem in connection with 16-bit
samples from libpng, an interface for reading and writing PNG
(Portable Network Graphics) format files.  The starting offsets for
the loops are calculated incorrectly which causes a buffer overrun
beyond the beginning of the row buffer.
For the current stable distribution (woody) this problem has been
fixed in version 1.0.12-3.woody.3 for libpng and in version
1.2.1-1.1.woody.3 for libpng3.
For the old stable distribution (potato) this problem has been fixed
in version 1.0.5-1.1 for libpng.  There are no other libpng packages.
For the unstable distribution (sid) this problem has been fixed in
version 1.0.12-7 for libpng and in version 1.2.5-8 for libpng3.
We recommend that you upgrade your libpng packages.


Solution : http://www.debian.org/security/2002/dsa-213
Risk factor : High';

if (description) {
 script_id(15050);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "213");
 script_cve_id("CVE-2002-1363");
 script_bugtraq_id(6431);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA213] DSA-213-1 libpng");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-213-1 libpng");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libpng2', release: '2.2', reference: '1.0.5-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpng2 is vulnerable in Debian 2.2.\nUpgrade to libpng2_1.0.5-1.1\n');
}
if (deb_check(prefix: 'libpng2-dev', release: '2.2', reference: '1.0.5-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpng2-dev is vulnerable in Debian 2.2.\nUpgrade to libpng2-dev_1.0.5-1.1\n');
}
if (deb_check(prefix: 'libpng-dev', release: '3.0', reference: '1.2.1-1.1.woody.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpng-dev is vulnerable in Debian 3.0.\nUpgrade to libpng-dev_1.2.1-1.1.woody.3\n');
}
if (deb_check(prefix: 'libpng2', release: '3.0', reference: '1.0.12-3.woody.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpng2 is vulnerable in Debian 3.0.\nUpgrade to libpng2_1.0.12-3.woody.3\n');
}
if (deb_check(prefix: 'libpng2-dev', release: '3.0', reference: '1.0.12-3.woody.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpng2-dev is vulnerable in Debian 3.0.\nUpgrade to libpng2-dev_1.0.12-3.woody.3\n');
}
if (deb_check(prefix: 'libpng3', release: '3.0', reference: '1.2.1-1.1.woody.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpng3 is vulnerable in Debian 3.0.\nUpgrade to libpng3_1.2.1-1.1.woody.3\n');
}
if (deb_check(prefix: 'libpng,', release: '3.1', reference: '1.0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpng, is vulnerable in Debian 3.1.\nUpgrade to libpng,_1.0\n');
}
if (deb_check(prefix: 'libpng,', release: '2.2', reference: '1.0.5-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpng, is vulnerable in Debian potato.\nUpgrade to libpng,_1.0.5-1\n');
}
if (deb_check(prefix: 'libpng,', release: '3.0', reference: '1.0.12-3.woody')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpng, is vulnerable in Debian woody.\nUpgrade to libpng,_1.0.12-3.woody\n');
}
if (w) { security_hole(port: 0, data: desc); }
