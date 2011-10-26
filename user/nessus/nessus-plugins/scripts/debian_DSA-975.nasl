# This script was automatically generated from the dsa-975
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Marcus Meissner discovered that attackers can trigger a buffer overflow
in the path handling code by creating or abusing existing symlinks, which
may lead to the execution of arbitrary code.
This vulnerability isn\'t present in the kernel NFS server.
This update includes a bugfix for attribute handling of symlinks. This
fix does not have security implications, but at the time when this DSA
was prepared it was already queued for the next stable point release, so
we decided to include it beforehand.
For the old stable distribution (woody) this problem has been fixed in
version 2.2beta47-12woody1.
For the stable distribution (sarge) this problem has been fixed in
version 2.2beta47-20sarge2.
For the unstable distribution (sid) this problem has been fixed in
version 2.2beta47-22.
We recommend that you upgrade your nfs-user-server package.


Solution : http://www.debian.org/security/2006/dsa-975
Risk factor : High';

if (description) {
 script_id(22841);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "975");
 script_cve_id("CVE-2006-0043");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA975] DSA-975-1 nfs-user-server");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-975-1 nfs-user-server");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'nfs-user-server', release: '', reference: '2.2beta47-22')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nfs-user-server is vulnerable in Debian .\nUpgrade to nfs-user-server_2.2beta47-22\n');
}
if (deb_check(prefix: 'nfs-user-server', release: '3.0', reference: '2.2beta47-12woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nfs-user-server is vulnerable in Debian 3.0.\nUpgrade to nfs-user-server_2.2beta47-12woody1\n');
}
if (deb_check(prefix: 'ugidd', release: '3.0', reference: '2.2beta47-12woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ugidd is vulnerable in Debian 3.0.\nUpgrade to ugidd_2.2beta47-12woody1\n');
}
if (deb_check(prefix: 'nfs-user-server', release: '3.1', reference: '2.2beta47-20sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nfs-user-server is vulnerable in Debian 3.1.\nUpgrade to nfs-user-server_2.2beta47-20sarge2\n');
}
if (deb_check(prefix: 'ugidd', release: '3.1', reference: '2.2beta47-20sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ugidd is vulnerable in Debian 3.1.\nUpgrade to ugidd_2.2beta47-20sarge2\n');
}
if (deb_check(prefix: 'nfs-user-server', release: '3.1', reference: '2.2beta47-20sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nfs-user-server is vulnerable in Debian sarge.\nUpgrade to nfs-user-server_2.2beta47-20sarge2\n');
}
if (deb_check(prefix: 'nfs-user-server', release: '3.0', reference: '2.2beta47-12woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nfs-user-server is vulnerable in Debian woody.\nUpgrade to nfs-user-server_2.2beta47-12woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
