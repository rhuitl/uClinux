# This script was automatically generated from the dsa-1123
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Luigi Auriemma discovered that DUMB, a tracker music library, performs
insufficient sanitising of values parsed from IT music files, which might
lead to a buffer overflow and execution of arbitrary code if manipulated
files are read.
For the stable distribution (sarge) this problem has been fixed in
version 0.9.2-6.
For the unstable distribution (sid) this problem has been fixed in
version 0.9.3-5.
We recommend that you upgrade your libdumb packages.


Solution : http://www.debian.org/security/2006/dsa-1123
Risk factor : High';

if (description) {
 script_id(22665);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1123");
 script_cve_id("CVE-2006-3668");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1123] DSA-1123-1 libdumb");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1123-1 libdumb");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libdumb', release: '', reference: '0.9.3-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libdumb is vulnerable in Debian .\nUpgrade to libdumb_0.9.3-5\n');
}
if (deb_check(prefix: 'libaldmb0', release: '3.1', reference: '0.9.2-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libaldmb0 is vulnerable in Debian 3.1.\nUpgrade to libaldmb0_0.9.2-6\n');
}
if (deb_check(prefix: 'libaldmb0-dev', release: '3.1', reference: '0.9.2-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libaldmb0-dev is vulnerable in Debian 3.1.\nUpgrade to libaldmb0-dev_0.9.2-6\n');
}
if (deb_check(prefix: 'libdumb0', release: '3.1', reference: '0.9.2-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libdumb0 is vulnerable in Debian 3.1.\nUpgrade to libdumb0_0.9.2-6\n');
}
if (deb_check(prefix: 'libdumb0-dev', release: '3.1', reference: '0.9.2-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libdumb0-dev is vulnerable in Debian 3.1.\nUpgrade to libdumb0-dev_0.9.2-6\n');
}
if (deb_check(prefix: 'libdumb', release: '3.1', reference: '0.9.2-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libdumb is vulnerable in Debian sarge.\nUpgrade to libdumb_0.9.2-6\n');
}
if (w) { security_hole(port: 0, data: desc); }
