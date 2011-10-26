# This script was automatically generated from the dsa-606
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
SGI has discovered that rpc.statd from the nfs-utils package, the
Network Status Monitor, did not ignore the "SIGPIPE".  Hence, a client
prematurely terminating the TCP connection could also terminate the
server process.
For the stable distribution (woody) this problem has been fixed in
version 1.0-2woody2.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you upgrade your nfs-utils package.


Solution : http://www.debian.org/security/2004/dsa-606
Risk factor : High';

if (description) {
 script_id(15925);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "606");
 script_cve_id("CVE-2004-1014");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA606] DSA-606-1 nfs-utils");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-606-1 nfs-utils");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'nfs-common', release: '3.0', reference: '1.0-2woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nfs-common is vulnerable in Debian 3.0.\nUpgrade to nfs-common_1.0-2woody3\n');
}
if (deb_check(prefix: 'nfs-kernel-server', release: '3.0', reference: '1.0-2woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nfs-kernel-server is vulnerable in Debian 3.0.\nUpgrade to nfs-kernel-server_1.0-2woody3\n');
}
if (deb_check(prefix: 'nhfsstone', release: '3.0', reference: '1.0-2woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nhfsstone is vulnerable in Debian 3.0.\nUpgrade to nhfsstone_1.0-2woody3\n');
}
if (deb_check(prefix: 'nfs-utils', release: '3.0', reference: '1.0-2woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nfs-utils is vulnerable in Debian woody.\nUpgrade to nfs-utils_1.0-2woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
