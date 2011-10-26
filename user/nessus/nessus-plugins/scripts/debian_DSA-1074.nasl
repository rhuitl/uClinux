# This script was automatically generated from the dsa-1074
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A. Alejandro Hernández discovered a vulnerability in mpg123, a
command-line player for MPEG audio files. Insufficient validation of
MPEG 2.0 layer 3 files results in several buffer overflows.
For the stable distribution (sarge) these problems have been fixed in
version 0.59r-20sarge1.
For the unstable distribution (sid) these problems have been fixed in
version 0.59r-22.
We recommend that you upgrade your mpg123 packages.


Solution : http://www.debian.org/security/2006/dsa-1074
Risk factor : High';

if (description) {
 script_id(22616);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1074");
 script_cve_id("CVE-2006-1655");
 script_bugtraq_id(17365);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1074] DSA-1074-1 mpg123");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1074-1 mpg123");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mpg123', release: '', reference: '0.59r-22')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mpg123 is vulnerable in Debian .\nUpgrade to mpg123_0.59r-22\n');
}
if (deb_check(prefix: 'mpg123', release: '3.1', reference: '0.59r-20sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mpg123 is vulnerable in Debian 3.1.\nUpgrade to mpg123_0.59r-20sarge1\n');
}
if (deb_check(prefix: 'mpg123-esd', release: '3.1', reference: '0.59r-20sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mpg123-esd is vulnerable in Debian 3.1.\nUpgrade to mpg123-esd_0.59r-20sarge1\n');
}
if (deb_check(prefix: 'mpg123-nas', release: '3.1', reference: '0.59r-20sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mpg123-nas is vulnerable in Debian 3.1.\nUpgrade to mpg123-nas_0.59r-20sarge1\n');
}
if (deb_check(prefix: 'mpg123-oss-3dnow', release: '3.1', reference: '0.59r-20sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mpg123-oss-3dnow is vulnerable in Debian 3.1.\nUpgrade to mpg123-oss-3dnow_0.59r-20sarge1\n');
}
if (deb_check(prefix: 'mpg123-oss-i486', release: '3.1', reference: '0.59r-20sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mpg123-oss-i486 is vulnerable in Debian 3.1.\nUpgrade to mpg123-oss-i486_0.59r-20sarge1\n');
}
if (deb_check(prefix: 'mpg123', release: '3.1', reference: '0.59r-20sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mpg123 is vulnerable in Debian sarge.\nUpgrade to mpg123_0.59r-20sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
