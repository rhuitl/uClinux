# This script was automatically generated from the dsa-280
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Digital Defense, Inc. has alerted the Samba Team to a serious
vulnerability in Samba, a LanManager-like file and printer server for Unix.
This vulnerability can lead to an anonymous user gaining root access
on a Samba serving system.  An exploit for this problem is already
circulating and in use.
Since the packages for potato are quite old it is likely that they
contain more security-relevant bugs that we don\'t know of.  You are
therefore advised to upgrade your systems running Samba to woody
soon.
Unofficial backported packages from the Samba maintainers for version
2.2.8 of Samba for woody are available at
~peloy and
~vorlon.
For the stable distribution (woody) this problem has been fixed in
version 2.2.3a-12.3.
For the old stable distribution (potato) this problem has been fixed in
version 2.0.7-5.1.
The unstable distribution (sid) is not affected since it contains
version 3.0 packages already.
We recommend that you upgrade your Samba packages immediately.


Solution : http://www.debian.org/security/2003/dsa-280
Risk factor : High';

if (description) {
 script_id(15117);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "280");
 script_cve_id("CVE-2003-0196", "CVE-2003-0201");
 script_bugtraq_id(7294, 7295);
 script_xref(name: "CERT", value: "267873");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA280] DSA-280-1 samba");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-280-1 samba");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'samba', release: '2.2', reference: '2.0.7-5.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package samba is vulnerable in Debian 2.2.\nUpgrade to samba_2.0.7-5.1\n');
}
if (deb_check(prefix: 'samba-common', release: '2.2', reference: '2.0.7-5.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package samba-common is vulnerable in Debian 2.2.\nUpgrade to samba-common_2.0.7-5.1\n');
}
if (deb_check(prefix: 'samba-doc', release: '2.2', reference: '2.0.7-5.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package samba-doc is vulnerable in Debian 2.2.\nUpgrade to samba-doc_2.0.7-5.1\n');
}
if (deb_check(prefix: 'smbclient', release: '2.2', reference: '2.0.7-5.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package smbclient is vulnerable in Debian 2.2.\nUpgrade to smbclient_2.0.7-5.1\n');
}
if (deb_check(prefix: 'smbfs', release: '2.2', reference: '2.0.7-5.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package smbfs is vulnerable in Debian 2.2.\nUpgrade to smbfs_2.0.7-5.1\n');
}
if (deb_check(prefix: 'swat', release: '2.2', reference: '2.0.7-5.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package swat is vulnerable in Debian 2.2.\nUpgrade to swat_2.0.7-5.1\n');
}
if (deb_check(prefix: 'libpam-smbpass', release: '3.0', reference: '2.2.3a-12.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpam-smbpass is vulnerable in Debian 3.0.\nUpgrade to libpam-smbpass_2.2.3a-12.3\n');
}
if (deb_check(prefix: 'libsmbclient', release: '3.0', reference: '2.2.3a-12.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libsmbclient is vulnerable in Debian 3.0.\nUpgrade to libsmbclient_2.2.3a-12.3\n');
}
if (deb_check(prefix: 'libsmbclient-dev', release: '3.0', reference: '2.2.3a-12.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libsmbclient-dev is vulnerable in Debian 3.0.\nUpgrade to libsmbclient-dev_2.2.3a-12.3\n');
}
if (deb_check(prefix: 'samba', release: '3.0', reference: '2.2.3a-12.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package samba is vulnerable in Debian 3.0.\nUpgrade to samba_2.2.3a-12.3\n');
}
if (deb_check(prefix: 'samba-common', release: '3.0', reference: '2.2.3a-12.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package samba-common is vulnerable in Debian 3.0.\nUpgrade to samba-common_2.2.3a-12.3\n');
}
if (deb_check(prefix: 'samba-doc', release: '3.0', reference: '2.2.3a-12.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package samba-doc is vulnerable in Debian 3.0.\nUpgrade to samba-doc_2.2.3a-12.3\n');
}
if (deb_check(prefix: 'smbclient', release: '3.0', reference: '2.2.3a-12.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package smbclient is vulnerable in Debian 3.0.\nUpgrade to smbclient_2.2.3a-12.3\n');
}
if (deb_check(prefix: 'smbfs', release: '3.0', reference: '2.2.3a-12.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package smbfs is vulnerable in Debian 3.0.\nUpgrade to smbfs_2.2.3a-12.3\n');
}
if (deb_check(prefix: 'swat', release: '3.0', reference: '2.2.3a-12.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package swat is vulnerable in Debian 3.0.\nUpgrade to swat_2.2.3a-12.3\n');
}
if (deb_check(prefix: 'winbind', release: '3.0', reference: '2.2.3a-12.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package winbind is vulnerable in Debian 3.0.\nUpgrade to winbind_2.2.3a-12.3\n');
}
if (deb_check(prefix: 'samba', release: '2.2', reference: '2.0.7-5.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package samba is vulnerable in Debian potato.\nUpgrade to samba_2.0.7-5.1\n');
}
if (deb_check(prefix: 'samba', release: '3.0', reference: '2.2.3a-12.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package samba is vulnerable in Debian woody.\nUpgrade to samba_2.2.3a-12.3\n');
}
if (w) { security_hole(port: 0, data: desc); }
