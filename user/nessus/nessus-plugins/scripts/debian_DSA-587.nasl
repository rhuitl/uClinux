# This script was automatically generated from the dsa-587
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Luigi Auriemma discovered a buffer overflow condition in the playlist
module of freeamp which could lead to arbitrary code execution.
Recent versions of freeamp were renamed into zinf.
For the stable distribution (woody) this problem has been fixed in
version 2.1.1.0-4woody2.
For the unstable distribution (sid) this problem does not exist in the
zinf package as the code in question was rewritten.
We recommend that you upgrade your freeamp packages.


Solution : http://www.debian.org/security/2004/dsa-587
Risk factor : High';

if (description) {
 script_id(15685);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "587");
 script_cve_id("CVE-2004-0964");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA587] DSA-587-1 freeamp");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-587-1 freeamp");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'freeamp', release: '3.0', reference: '2.1.1.0-4woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freeamp is vulnerable in Debian 3.0.\nUpgrade to freeamp_2.1.1.0-4woody2\n');
}
if (deb_check(prefix: 'freeamp-doc', release: '3.0', reference: '2.1.1.0-4woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freeamp-doc is vulnerable in Debian 3.0.\nUpgrade to freeamp-doc_2.1.1.0-4woody2\n');
}
if (deb_check(prefix: 'freeamp-extras', release: '3.0', reference: '2.1.1.0-4woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freeamp-extras is vulnerable in Debian 3.0.\nUpgrade to freeamp-extras_2.1.1.0-4woody2\n');
}
if (deb_check(prefix: 'libfreeamp-alsa', release: '3.0', reference: '2.1.1.0-4woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libfreeamp-alsa is vulnerable in Debian 3.0.\nUpgrade to libfreeamp-alsa_2.1.1.0-4woody2\n');
}
if (deb_check(prefix: 'libfreeamp-esound', release: '3.0', reference: '2.1.1.0-4woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libfreeamp-esound is vulnerable in Debian 3.0.\nUpgrade to libfreeamp-esound_2.1.1.0-4woody2\n');
}
if (deb_check(prefix: 'freeamp', release: '3.0', reference: '2.1.1.0-4woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freeamp is vulnerable in Debian woody.\nUpgrade to freeamp_2.1.1.0-4woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
