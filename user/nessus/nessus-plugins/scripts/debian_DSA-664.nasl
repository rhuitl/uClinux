# This script was automatically generated from the dsa-664
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
It has been discovered, that cpio, a program to manage archives of
files, creates output files with -O and -F with broken permissions due
to a reset zero umask which allows local users to read or overwrite
those files.
For the stable distribution (woody) this problem has been fixed in
version 2.4.2-39woody1.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you upgrade your cpio package.


Solution : http://www.debian.org/security/2005/dsa-664
Risk factor : High';

if (description) {
 script_id(16300);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "664");
 script_cve_id("CVE-1999-1572");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA664] DSA-664-1 cpio");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-664-1 cpio");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'cpio', release: '3.0', reference: '2.4.2-39woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cpio is vulnerable in Debian 3.0.\nUpgrade to cpio_2.4.2-39woody1\n');
}
if (deb_check(prefix: 'cpio', release: '3.0', reference: '2.4.2-39woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cpio is vulnerable in Debian woody.\nUpgrade to cpio_2.4.2-39woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
