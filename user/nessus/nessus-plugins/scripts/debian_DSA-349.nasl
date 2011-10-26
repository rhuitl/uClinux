# This script was automatically generated from the dsa-349
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The logging code in nfs-utils contains an off-by-one buffer overrun
when adding a newline to the string being logged.  This vulnerability
may allow an attacker to execute arbitrary code or cause a denial of
service condition by sending certain RPC requests.
For the stable distribution (woody) this problem has been fixed in
version 1:1.0-2woody1.
For the unstable distribution (sid) this problem has been fixed in
version 1:1.0.3-2.
We recommend that you update your nfs-utils package.


Solution : http://www.debian.org/security/2003/dsa-349
Risk factor : High';

if (description) {
 script_id(15186);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "349");
 script_cve_id("CVE-2003-0252");
 script_bugtraq_id(8179);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA349] DSA-349-1 nfs-utils");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-349-1 nfs-utils");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'nfs-common', release: '3.0', reference: '1.0-2woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nfs-common is vulnerable in Debian 3.0.\nUpgrade to nfs-common_1.0-2woody1\n');
}
if (deb_check(prefix: 'nfs-kernel-server', release: '3.0', reference: '1.0-2woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nfs-kernel-server is vulnerable in Debian 3.0.\nUpgrade to nfs-kernel-server_1.0-2woody1\n');
}
if (deb_check(prefix: 'nhfsstone', release: '3.0', reference: '1.0-2woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nhfsstone is vulnerable in Debian 3.0.\nUpgrade to nhfsstone_1.0-2woody1\n');
}
if (deb_check(prefix: 'nfs-utils', release: '3.1', reference: '1.0.3-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nfs-utils is vulnerable in Debian 3.1.\nUpgrade to nfs-utils_1.0.3-2\n');
}
if (deb_check(prefix: 'nfs-utils', release: '3.0', reference: '1.0-2woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nfs-utils is vulnerable in Debian woody.\nUpgrade to nfs-utils_1.0-2woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
