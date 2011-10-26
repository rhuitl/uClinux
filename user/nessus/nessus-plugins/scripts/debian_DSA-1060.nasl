# This script was automatically generated from the dsa-1060
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Jan Rekorajski discovered that the kernel patch for virtual private servers
does not limit context capabilities to the root user within the virtual
server, which might lead to privilege escalation for some virtual server
specific operations.
The old stable distribution (woody) does not contain kernel-patch-vserver
packages.
For the stable distribution (sarge) this problem has been fixed in
version 1.9.5.6.
For the unstable distribution (sid) this problem has been fixed in
version 2.0.1-4.
We recommend that you upgrade your kernel-patch-vserver package and
rebuild your kernel immediately.


Solution : http://www.debian.org/security/2006/dsa-1060
Risk factor : High';

if (description) {
 script_id(22602);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1060");
 script_cve_id("CVE-2006-2110");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1060] DSA-1060-1 kernel-patch-vserver");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1060-1 kernel-patch-vserver");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'kernel-patch-vserver', release: '', reference: '2.0.1-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-vserver is vulnerable in Debian .\nUpgrade to kernel-patch-vserver_2.0.1-4\n');
}
if (deb_check(prefix: 'kernel-patch-vserver', release: '3.1', reference: '1.9.5.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-vserver is vulnerable in Debian 3.1.\nUpgrade to kernel-patch-vserver_1.9.5.6\n');
}
if (deb_check(prefix: 'kernel-patch-vserver', release: '3.1', reference: '1.9.5.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-vserver is vulnerable in Debian sarge.\nUpgrade to kernel-patch-vserver_1.9.5.6\n');
}
if (w) { security_hole(port: 0, data: desc); }
