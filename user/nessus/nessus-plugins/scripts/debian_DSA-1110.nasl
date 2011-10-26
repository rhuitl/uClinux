# This script was automatically generated from the dsa-1110
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Gerald Carter discovered that the smbd daemon from Samba, a free
implementation of the SMB/CIFS protocol, imposes insufficient limits
in the code to handle shared connections, which can be exploited to
exhaust system memory by sending maliciously crafted requests, leading
to denial of service.
For the stable distribution (sarge) this problem has been fixed in
version 3.0.14a-3sarge2.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you upgrade your samba package.


Solution : http://www.debian.org/security/2006/dsa-1110
Risk factor : High';

if (description) {
 script_id(22652);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1110");
 script_cve_id("CVE-2006-3403");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1110] DSA-1110-1 samba");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1110-1 samba");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libpam-smbpass', release: '3.1', reference: '3.0.14a-3sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpam-smbpass is vulnerable in Debian 3.1.\nUpgrade to libpam-smbpass_3.0.14a-3sarge2\n');
}
if (deb_check(prefix: 'libsmbclient', release: '3.1', reference: '3.0.14a-3sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libsmbclient is vulnerable in Debian 3.1.\nUpgrade to libsmbclient_3.0.14a-3sarge2\n');
}
if (deb_check(prefix: 'libsmbclient-dev', release: '3.1', reference: '3.0.14a-3sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libsmbclient-dev is vulnerable in Debian 3.1.\nUpgrade to libsmbclient-dev_3.0.14a-3sarge2\n');
}
if (deb_check(prefix: 'python2.3-samba', release: '3.1', reference: '3.0.14a-3sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.3-samba is vulnerable in Debian 3.1.\nUpgrade to python2.3-samba_3.0.14a-3sarge2\n');
}
if (deb_check(prefix: 'samba', release: '3.1', reference: '3.0.14a-3sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package samba is vulnerable in Debian 3.1.\nUpgrade to samba_3.0.14a-3sarge2\n');
}
if (deb_check(prefix: 'samba-common', release: '3.1', reference: '3.0.14a-3sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package samba-common is vulnerable in Debian 3.1.\nUpgrade to samba-common_3.0.14a-3sarge2\n');
}
if (deb_check(prefix: 'samba-dbg', release: '3.1', reference: '3.0.14a-3sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package samba-dbg is vulnerable in Debian 3.1.\nUpgrade to samba-dbg_3.0.14a-3sarge2\n');
}
if (deb_check(prefix: 'samba-doc', release: '3.1', reference: '3.0.14a-3sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package samba-doc is vulnerable in Debian 3.1.\nUpgrade to samba-doc_3.0.14a-3sarge2\n');
}
if (deb_check(prefix: 'smbclient', release: '3.1', reference: '3.0.14a-3sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package smbclient is vulnerable in Debian 3.1.\nUpgrade to smbclient_3.0.14a-3sarge2\n');
}
if (deb_check(prefix: 'smbfs', release: '3.1', reference: '3.0.14a-3sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package smbfs is vulnerable in Debian 3.1.\nUpgrade to smbfs_3.0.14a-3sarge2\n');
}
if (deb_check(prefix: 'swat', release: '3.1', reference: '3.0.14a-3sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package swat is vulnerable in Debian 3.1.\nUpgrade to swat_3.0.14a-3sarge2\n');
}
if (deb_check(prefix: 'winbind', release: '3.1', reference: '3.0.14a-3sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package winbind is vulnerable in Debian 3.1.\nUpgrade to winbind_3.0.14a-3sarge2\n');
}
if (deb_check(prefix: 'samba', release: '3.1', reference: '3.0.14a-3sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package samba is vulnerable in Debian sarge.\nUpgrade to samba_3.0.14a-3sarge2\n');
}
if (w) { security_hole(port: 0, data: desc); }
