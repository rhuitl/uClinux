# This script was automatically generated from the dsa-730
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Imran Ghory discovered a race condition in bzip2, a high-quality
block-sorting file compressor and decompressor.  When decompressing a
file in a directory an attacker has access to, bunzip2 could be
tricked to set the file permissions to a different file the user has
permissions to.
For the stable distribution (woody) this problem has been fixed in
version 1.0.2-1.woody2.
For the testing distribution (sarge) this problem has been fixed in
version 1.0.2-6.
For the unstable distribution (sid) this problem has been fixed in
version 1.0.2-6.
We recommend that you upgrade your bzip2 packages.


Solution : http://www.debian.org/security/2005/dsa-730
Risk factor : High';

if (description) {
 script_id(18517);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "730");
 script_cve_id("CVE-2005-0953");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA730] DSA-730-1 bzip2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-730-1 bzip2");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'bzip2', release: '3.0', reference: '1.0.2-1.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bzip2 is vulnerable in Debian 3.0.\nUpgrade to bzip2_1.0.2-1.woody2\n');
}
if (deb_check(prefix: 'libbz2-1.0', release: '3.0', reference: '1.0.2-1.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libbz2-1.0 is vulnerable in Debian 3.0.\nUpgrade to libbz2-1.0_1.0.2-1.woody2\n');
}
if (deb_check(prefix: 'libbz2-dev', release: '3.0', reference: '1.0.2-1.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libbz2-dev is vulnerable in Debian 3.0.\nUpgrade to libbz2-dev_1.0.2-1.woody2\n');
}
if (deb_check(prefix: 'bzip2', release: '3.1', reference: '1.0.2-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bzip2 is vulnerable in Debian 3.1.\nUpgrade to bzip2_1.0.2-6\n');
}
if (deb_check(prefix: 'bzip2', release: '3.1', reference: '1.0.2-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bzip2 is vulnerable in Debian sarge.\nUpgrade to bzip2_1.0.2-6\n');
}
if (deb_check(prefix: 'bzip2', release: '3.0', reference: '1.0.2-1.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bzip2 is vulnerable in Debian woody.\nUpgrade to bzip2_1.0.2-1.woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
