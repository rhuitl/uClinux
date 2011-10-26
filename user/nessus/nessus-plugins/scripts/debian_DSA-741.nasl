# This script was automatically generated from the dsa-741
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Chris Evans discovered that a specially crafted archive can trigger an
infinite loop in bzip2, a high-quality block-sorting file compressor.
During uncompression this results in an indefinitely growing output
file which will finally fill up the disk.  On systems that
automatically decompress bzip2 archives this can cause a denial of
service.
For the oldstable distribution (woody) this problem has been fixed in
version 1.0.2-1.woody5.
For the stable distribution (sarge) this problem has been fixed in
version 1.0.2-7.
For the unstable distribution (sid) this problem has been fixed in
version 1.0.2-7.
We recommend that you upgrade your bzip2 package.


Solution : http://www.debian.org/security/2005/dsa-741
Risk factor : High';

if (description) {
 script_id(18645);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "741");
 script_cve_id("CVE-2005-1260");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA741] DSA-741-1 bzip2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-741-1 bzip2");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'bzip2', release: '3.0', reference: '1.0.2-1.woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bzip2 is vulnerable in Debian 3.0.\nUpgrade to bzip2_1.0.2-1.woody5\n');
}
if (deb_check(prefix: 'libbz2-1.0', release: '3.0', reference: '1.0.2-1.woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libbz2-1.0 is vulnerable in Debian 3.0.\nUpgrade to libbz2-1.0_1.0.2-1.woody5\n');
}
if (deb_check(prefix: 'libbz2-dev', release: '3.0', reference: '1.0.2-1.woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libbz2-dev is vulnerable in Debian 3.0.\nUpgrade to libbz2-dev_1.0.2-1.woody5\n');
}
if (deb_check(prefix: 'bzip2', release: '3.1', reference: '1.0.2-7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bzip2 is vulnerable in Debian 3.1.\nUpgrade to bzip2_1.0.2-7\n');
}
if (deb_check(prefix: 'bzip2', release: '3.1', reference: '1.0.2-7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bzip2 is vulnerable in Debian sarge.\nUpgrade to bzip2_1.0.2-7\n');
}
if (deb_check(prefix: 'bzip2', release: '3.0', reference: '1.0.2-1.woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bzip2 is vulnerable in Debian woody.\nUpgrade to bzip2_1.0.2-1.woody5\n');
}
if (w) { security_hole(port: 0, data: desc); }
