# This script was automatically generated from the dsa-1138
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Carlo Contavalli discovered an integer overflow in CFS, a cryptographic
filesystem, which allows local users to crash the encryption daemon.
For the stable distribution (sarge) this problem has been fixed in
version 1.4.1-15sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 1.4.1-17.
We recommend that you upgrade your cfs package.


Solution : http://www.debian.org/security/2006/dsa-1138
Risk factor : High';

if (description) {
 script_id(22680);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1138");
 script_cve_id("CVE-2006-3123");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1138] DSA-1138-1 cfs");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1138-1 cfs");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'cfs', release: '', reference: '1.4.1-17')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cfs is vulnerable in Debian .\nUpgrade to cfs_1.4.1-17\n');
}
if (deb_check(prefix: 'cfs', release: '3.1', reference: '1.4.1-15sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cfs is vulnerable in Debian 3.1.\nUpgrade to cfs_1.4.1-15sarge1\n');
}
if (deb_check(prefix: 'cfs', release: '3.1', reference: '1.4.1-15sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cfs is vulnerable in Debian sarge.\nUpgrade to cfs_1.4.1-15sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
