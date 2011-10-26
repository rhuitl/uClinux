# This script was automatically generated from the dsa-678
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
"Vlad902" discovered a vulnerability in the rwhod program that can be
used to crash the listening process.  The broadcasting one is
unaffected.  This vulnerability only affects little endian
architectures (i.e. on Debian: alpha, arm, ia64, i386, mipsel,
and s390).
For the stable distribution (woody) this problem has been fixed in
version 0.17-4woody2.
For the unstable distribution (sid) this problem has been fixed in
version 0.17-8.
We recommend that you upgrade your rwhod package.


Solution : http://www.debian.org/security/2005/dsa-678
Risk factor : High';

if (description) {
 script_id(16382);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "678");
 script_cve_id("CVE-2004-1180");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA678] DSA-678-1 netkit-rwho");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-678-1 netkit-rwho");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'rwho', release: '3.0', reference: '0.17-4woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package rwho is vulnerable in Debian 3.0.\nUpgrade to rwho_0.17-4woody2\n');
}
if (deb_check(prefix: 'rwhod', release: '3.0', reference: '0.17-4woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package rwhod is vulnerable in Debian 3.0.\nUpgrade to rwhod_0.17-4woody2\n');
}
if (deb_check(prefix: 'netkit-rwho', release: '3.1', reference: '0.17-8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package netkit-rwho is vulnerable in Debian 3.1.\nUpgrade to netkit-rwho_0.17-8\n');
}
if (deb_check(prefix: 'netkit-rwho', release: '3.0', reference: '0.17-4woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package netkit-rwho is vulnerable in Debian woody.\nUpgrade to netkit-rwho_0.17-4woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
