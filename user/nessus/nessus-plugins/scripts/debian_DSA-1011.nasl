# This script was automatically generated from the dsa-1011
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several vulnerabilities have been discovered in the Debian vserver
support for Linux.  The Common Vulnerabilities and Exposures project
identifies the following problems:
    Bjørn Steinbrink discovered that the chroot barrier is not set
    correctly with util-vserver which may result in unauthorised
    escapes from a vserver to the host system.
    This vulnerability is limited to the 2.4 kernel patch included in
    kernel-patch-vserver.  The correction to this problem requires
    updating the util-vserver package as well and installing a new
    kernel built from the updated kernel-patch-vserver package.
    The default policy of util-vserver is set to trust all unknown
    capabilities instead of considering them as insecure.
The old stable distribution (woody) does not contain a
kernel-patch-vserver package.
For the stable distribution (sarge) this problem has been fixed in
version 1.9.5.5 of kernel-patch-vserver and in version
0.30.204-5sarge3 of util-vserver.
For the unstable distribution (sid) this problem has been fixed in
version 2.3 of kernel-patch-vserver and in version 0.30.208-1 of
util-vserver.
We recommend that you upgrade your util-vserver and
kernel-patch-vserver packages and build a new kernel immediately.


Solution : http://www.debian.org/security/2006/dsa-1011
Risk factor : High';

if (description) {
 script_id(22553);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1011");
 script_cve_id("CVE-2005-4347", "CVE-2005-4418");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1011] DSA-1011-1 kernel-patch-vserver");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1011-1 kernel-patch-vserver");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'kernel-patch-vserver,', release: '', reference: '2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-vserver, is vulnerable in Debian .\nUpgrade to kernel-patch-vserver,_2\n');
}
if (deb_check(prefix: 'kernel-patch-vserver', release: '3.1', reference: '1.9.5.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-vserver is vulnerable in Debian 3.1.\nUpgrade to kernel-patch-vserver_1.9.5.5\n');
}
if (deb_check(prefix: 'util-vserver', release: '3.1', reference: '0.30.204-5sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package util-vserver is vulnerable in Debian 3.1.\nUpgrade to util-vserver_0.30.204-5sarge3\n');
}
if (deb_check(prefix: 'kernel-patch-vserver,', release: '3.1', reference: '1.9.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-vserver, is vulnerable in Debian sarge.\nUpgrade to kernel-patch-vserver,_1.9.5\n');
}
if (w) { security_hole(port: 0, data: desc); }
