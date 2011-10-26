# This script was automatically generated from the dsa-823
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
David Watson discovered a bug in mount as provided by util-linux and
other packages such as loop-aes-utils that allows local users to
bypass filesystem access restrictions by re-mounting it read-only.
For the old stable distribution (woody) this problem has been fixed in
version 2.11n-7woody1.
For the stable distribution (sarge) this problem has been fixed in
version 2.12p-4sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 2.12p-8.
We recommend that you upgrade your util-linux package.


Solution : http://www.debian.org/security/2005/dsa-823
Risk factor : High';

if (description) {
 script_id(19792);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "823");
 script_cve_id("CVE-2005-2876");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA823] DSA-823-1 util-linux");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-823-1 util-linux");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'util-linux', release: '', reference: '2.12p-8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package util-linux is vulnerable in Debian .\nUpgrade to util-linux_2.12p-8\n');
}
if (deb_check(prefix: 'bsdutils', release: '3.0', reference: '2.11n-7woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bsdutils is vulnerable in Debian 3.0.\nUpgrade to bsdutils_2.11n-7woody1\n');
}
if (deb_check(prefix: 'mount', release: '3.0', reference: '2.11n-7woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mount is vulnerable in Debian 3.0.\nUpgrade to mount_2.11n-7woody1\n');
}
if (deb_check(prefix: 'util-linux', release: '3.0', reference: '2.11n-7woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package util-linux is vulnerable in Debian 3.0.\nUpgrade to util-linux_2.11n-7woody1\n');
}
if (deb_check(prefix: 'util-linux-locales', release: '3.0', reference: '2.11n-7woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package util-linux-locales is vulnerable in Debian 3.0.\nUpgrade to util-linux-locales_2.11n-7woody1\n');
}
if (deb_check(prefix: 'bsdutils', release: '3.1', reference: '2.12p-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bsdutils is vulnerable in Debian 3.1.\nUpgrade to bsdutils_2.12p-4sarge1\n');
}
if (deb_check(prefix: 'mount', release: '3.1', reference: '2.12p-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mount is vulnerable in Debian 3.1.\nUpgrade to mount_2.12p-4sarge1\n');
}
if (deb_check(prefix: 'util-linux', release: '3.1', reference: '2.12p-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package util-linux is vulnerable in Debian 3.1.\nUpgrade to util-linux_2.12p-4sarge1\n');
}
if (deb_check(prefix: 'util-linux-locales', release: '3.1', reference: '2.12p-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package util-linux-locales is vulnerable in Debian 3.1.\nUpgrade to util-linux-locales_2.12p-4sarge1\n');
}
if (deb_check(prefix: 'util-linux', release: '3.1', reference: '2.12p-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package util-linux is vulnerable in Debian sarge.\nUpgrade to util-linux_2.12p-4sarge1\n');
}
if (deb_check(prefix: 'util-linux', release: '3.0', reference: '2.11n-7woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package util-linux is vulnerable in Debian woody.\nUpgrade to util-linux_2.11n-7woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
