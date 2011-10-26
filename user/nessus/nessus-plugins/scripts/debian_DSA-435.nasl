# This script was automatically generated from the dsa-435
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A vulnerability was discovered in mpg123, a command-line mp3 player,
whereby a response from a remote HTTP server could overflow a buffer
allocated on the heap, potentially permitting execution of arbitrary
code with the privileges of the user invoking mpg123.  In order for
this vulnerability to be exploited, mpg123 would need to request an
mp3 stream from a malicious remote server via HTTP.
For the current stable distribution (woody) this problem has been
fixed in version 0.59r-13woody2.
For the unstable distribution (sid) this problem has been fixed in
version 0.59r-15.
We recommend that you update your mpg123 package.


Solution : http://www.debian.org/security/2004/dsa-435
Risk factor : High';

if (description) {
 script_id(15272);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "435");
 script_cve_id("CVE-2003-0865");
 script_bugtraq_id(8680);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA435] DSA-435-1 mpg123");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-435-1 mpg123");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mpg123', release: '3.0', reference: '0.59r-13woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mpg123 is vulnerable in Debian 3.0.\nUpgrade to mpg123_0.59r-13woody2\n');
}
if (deb_check(prefix: 'mpg123-esd', release: '3.0', reference: '0.59r-13woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mpg123-esd is vulnerable in Debian 3.0.\nUpgrade to mpg123-esd_0.59r-13woody2\n');
}
if (deb_check(prefix: 'mpg123-nas', release: '3.0', reference: '0.59r-13woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mpg123-nas is vulnerable in Debian 3.0.\nUpgrade to mpg123-nas_0.59r-13woody2\n');
}
if (deb_check(prefix: 'mpg123-oss-3dnow', release: '3.0', reference: '0.59r-13woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mpg123-oss-3dnow is vulnerable in Debian 3.0.\nUpgrade to mpg123-oss-3dnow_0.59r-13woody2\n');
}
if (deb_check(prefix: 'mpg123-oss-i486', release: '3.0', reference: '0.59r-13woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mpg123-oss-i486 is vulnerable in Debian 3.0.\nUpgrade to mpg123-oss-i486_0.59r-13woody2\n');
}
if (deb_check(prefix: 'mpg123', release: '3.1', reference: '0.59r-15')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mpg123 is vulnerable in Debian 3.1.\nUpgrade to mpg123_0.59r-15\n');
}
if (deb_check(prefix: 'mpg123', release: '3.0', reference: '0.59r-13woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mpg123 is vulnerable in Debian woody.\nUpgrade to mpg123_0.59r-13woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
