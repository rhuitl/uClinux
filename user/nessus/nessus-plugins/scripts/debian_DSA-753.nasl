# This script was automatically generated from the dsa-753
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A format string vulnerability has been discovered in gedit, a
light-weight text editor for GNOME, that may allow attackers to cause
a denial of service (application crash) via a binary file with format
string specifiers in the filename.  Since gedit supports opening files
via "http://" URLs (through GNOME vfs) and other schemes, this might
be a remotely exploitable vulnerability.
The old stable distribution (woody) is not vulnerable to this problem.
For the stable distribution (sarge) this problem has been fixed in
version 2.8.3-4sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 2.10.3-1.
We recommend that you upgrade your gedit package.


Solution : http://www.debian.org/security/2005/dsa-753
Risk factor : High';

if (description) {
 script_id(18674);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "753");
 script_cve_id("CVE-2005-1686");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA753] DSA-753-1 gedit");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-753-1 gedit");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gedit', release: '', reference: '2.10.3-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gedit is vulnerable in Debian .\nUpgrade to gedit_2.10.3-1\n');
}
if (deb_check(prefix: 'gedit', release: '3.1', reference: '2.8.3-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gedit is vulnerable in Debian 3.1.\nUpgrade to gedit_2.8.3-4sarge1\n');
}
if (deb_check(prefix: 'gedit-common', release: '3.1', reference: '2.8.3-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gedit-common is vulnerable in Debian 3.1.\nUpgrade to gedit-common_2.8.3-4sarge1\n');
}
if (deb_check(prefix: 'gedit-dev', release: '3.1', reference: '2.8.3-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gedit-dev is vulnerable in Debian 3.1.\nUpgrade to gedit-dev_2.8.3-4sarge1\n');
}
if (deb_check(prefix: 'gedit', release: '3.1', reference: '2.8.3-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gedit is vulnerable in Debian sarge.\nUpgrade to gedit_2.8.3-4sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
