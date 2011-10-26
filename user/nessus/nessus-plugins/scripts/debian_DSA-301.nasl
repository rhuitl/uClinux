# This script was automatically generated from the dsa-301
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The gtop daemon, used for monitoring remote machines, contains a
buffer overflow which could be used by an attacker to execute
arbitrary code with the privileges of the daemon process.  If started
as root, the daemon process drops root privileges, assuming uid and
gid 99 by default.
This bug was previously fixed in DSA-098, but one of the patches was
not carried over to later versions of libgtop.
For the stable distribution (woody), this problem has been fixed in
version 1.0.13-3.1.
For the old stable distribution (potato), this problem was fixed in
DSA-098.
For the unstable distribution (sid), this problem has been fixed in
version 1.0.13-4.
We recommend that you update your libgtop package.


Solution : http://www.debian.org/security/2003/dsa-301
Risk factor : High';

if (description) {
 script_id(15138);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "301");
 script_cve_id("CVE-2001-0928");
 script_bugtraq_id(3594);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA301] DSA-301-1 libgtop");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-301-1 libgtop");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libgtop-daemon', release: '3.0', reference: '1.0.13-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgtop-daemon is vulnerable in Debian 3.0.\nUpgrade to libgtop-daemon_1.0.13-3.1\n');
}
if (deb_check(prefix: 'libgtop-dev', release: '3.0', reference: '1.0.13-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgtop-dev is vulnerable in Debian 3.0.\nUpgrade to libgtop-dev_1.0.13-3.1\n');
}
if (deb_check(prefix: 'libgtop1', release: '3.0', reference: '1.0.13-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgtop1 is vulnerable in Debian 3.0.\nUpgrade to libgtop1_1.0.13-3.1\n');
}
if (deb_check(prefix: 'libgtop', release: '3.1', reference: '1.0.13-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgtop is vulnerable in Debian 3.1.\nUpgrade to libgtop_1.0.13-4\n');
}
if (deb_check(prefix: 'libgtop', release: '3.0', reference: '1.0.13-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgtop is vulnerable in Debian woody.\nUpgrade to libgtop_1.0.13-3.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
