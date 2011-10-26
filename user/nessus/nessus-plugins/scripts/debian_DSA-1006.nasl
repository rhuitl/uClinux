# This script was automatically generated from the dsa-1006
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
"kcope" discovered that the wzdftpd FTP server lacks input sanitising
for the SITE command, which may lead to the execution of arbitrary
shell commands.
The old stable distribution (woody) does not contain wzdftpd packages.
For the stable distribution (sarge) this problem has been fixed in
version 0.5.2-1.1sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 0.5.5-1.
We recommend that you upgrade your wzdftpd package.


Solution : http://www.debian.org/security/2006/dsa-1006
Risk factor : High';

if (description) {
 script_id(22548);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1006");
 script_cve_id("CVE-2005-3081");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1006] DSA-1006-1 wzdftpd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1006-1 wzdftpd");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'wzdftpd', release: '', reference: '0.5.5-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package wzdftpd is vulnerable in Debian .\nUpgrade to wzdftpd_0.5.5-1\n');
}
if (deb_check(prefix: 'wzdftpd', release: '3.1', reference: '0.5.2-1.1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package wzdftpd is vulnerable in Debian 3.1.\nUpgrade to wzdftpd_0.5.2-1.1sarge1\n');
}
if (deb_check(prefix: 'wzdftpd-back-mysql', release: '3.1', reference: '0.5.2-1.1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package wzdftpd-back-mysql is vulnerable in Debian 3.1.\nUpgrade to wzdftpd-back-mysql_0.5.2-1.1sarge1\n');
}
if (deb_check(prefix: 'wzdftpd-dev', release: '3.1', reference: '0.5.2-1.1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package wzdftpd-dev is vulnerable in Debian 3.1.\nUpgrade to wzdftpd-dev_0.5.2-1.1sarge1\n');
}
if (deb_check(prefix: 'wzdftpd-mod-perl', release: '3.1', reference: '0.5.2-1.1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package wzdftpd-mod-perl is vulnerable in Debian 3.1.\nUpgrade to wzdftpd-mod-perl_0.5.2-1.1sarge1\n');
}
if (deb_check(prefix: 'wzdftpd-mod-tcl', release: '3.1', reference: '0.5.2-1.1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package wzdftpd-mod-tcl is vulnerable in Debian 3.1.\nUpgrade to wzdftpd-mod-tcl_0.5.2-1.1sarge1\n');
}
if (deb_check(prefix: 'wzdftpd', release: '3.1', reference: '0.5.2-1.1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package wzdftpd is vulnerable in Debian sarge.\nUpgrade to wzdftpd_0.5.2-1.1sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
