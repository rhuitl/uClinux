# This script was automatically generated from the dsa-960
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The former update caused temporary files to be created in the current
working directory due to a wrong function argument.  This update will
create temporary files in the users home directory if HOME is set or
in the common temporary directory otherwise, usually /tmp.  For
completeness below is a copy of the original advisory text:
Niko Tyni discovered that the Mail::Audit module, a Perl library for
creating simple mail filters, logs to a temporary file with a
predictable filename in an insecure fashion when logging is turned on,
which is not the case by default.
For the old stable distribution (woody) these problems have been fixed in
version 2.0-4woody3.
For the stable distribution (sarge) these problems have been fixed in
version 2.1-5sarge4.
For the unstable distribution (sid) these problems have been fixed in
version 2.1-5.1.
We recommend that you upgrade your libmail-audit-perl package.


Solution : http://www.debian.org/security/2006/dsa-960
Risk factor : High';

if (description) {
 script_id(22826);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "960");
 script_cve_id("CVE-2005-4536");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA960] DSA-960-3 libmail-audit-perl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-960-3 libmail-audit-perl");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libmail-audit-perl', release: '', reference: '2.1-5.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmail-audit-perl is vulnerable in Debian .\nUpgrade to libmail-audit-perl_2.1-5.1\n');
}
if (deb_check(prefix: 'libmail-audit-perl', release: '3.0', reference: '2.0-4woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmail-audit-perl is vulnerable in Debian 3.0.\nUpgrade to libmail-audit-perl_2.0-4woody3\n');
}
if (deb_check(prefix: 'mail-audit-tools', release: '3.0', reference: '2.0-4woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mail-audit-tools is vulnerable in Debian 3.0.\nUpgrade to mail-audit-tools_2.0-4woody3\n');
}
if (deb_check(prefix: 'libmail-audit-perl', release: '3.1', reference: '2.1-5sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmail-audit-perl is vulnerable in Debian 3.1.\nUpgrade to libmail-audit-perl_2.1-5sarge4\n');
}
if (deb_check(prefix: 'mail-audit-tools', release: '3.1', reference: '2.1-5sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mail-audit-tools is vulnerable in Debian 3.1.\nUpgrade to mail-audit-tools_2.1-5sarge4\n');
}
if (deb_check(prefix: 'libmail-audit-perl', release: '3.1', reference: '2.1-5sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmail-audit-perl is vulnerable in Debian sarge.\nUpgrade to libmail-audit-perl_2.1-5sarge4\n');
}
if (deb_check(prefix: 'libmail-audit-perl', release: '3.0', reference: '2.0-4woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmail-audit-perl is vulnerable in Debian woody.\nUpgrade to libmail-audit-perl_2.0-4woody3\n');
}
if (w) { security_hole(port: 0, data: desc); }
