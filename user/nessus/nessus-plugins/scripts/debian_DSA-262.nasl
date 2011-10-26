# This script was automatically generated from the dsa-262
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Sebastian Krahmer of the SuSE security audit team found two problems
in samba, a popular SMB/CIFS implementation. The problems are:
Both problems have been fixed in upstream version 2.2.8, and version
2.2.3a-12.1 of package for Debian GNU/Linux 3.0/woody.


Solution : http://www.debian.org/security/2003/dsa-262
Risk factor : High';

if (description) {
 script_id(15099);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "262");
 script_cve_id("CVE-2003-0085", "CVE-2003-0086");
 script_bugtraq_id(7106, 7107);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA262] DSA-262-1 samba");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-262-1 samba");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libpam-smbpass', release: '3.0', reference: '2.2.3a-12.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpam-smbpass is vulnerable in Debian 3.0.\nUpgrade to libpam-smbpass_2.2.3a-12.1\n');
}
if (deb_check(prefix: 'libsmbclient', release: '3.0', reference: '2.2.3a-12.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libsmbclient is vulnerable in Debian 3.0.\nUpgrade to libsmbclient_2.2.3a-12.1\n');
}
if (deb_check(prefix: 'libsmbclient-dev', release: '3.0', reference: '2.2.3a-12.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libsmbclient-dev is vulnerable in Debian 3.0.\nUpgrade to libsmbclient-dev_2.2.3a-12.1\n');
}
if (deb_check(prefix: 'samba', release: '3.0', reference: '2.2.3a-12.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package samba is vulnerable in Debian 3.0.\nUpgrade to samba_2.2.3a-12.1\n');
}
if (deb_check(prefix: 'samba-common', release: '3.0', reference: '2.2.3a-12.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package samba-common is vulnerable in Debian 3.0.\nUpgrade to samba-common_2.2.3a-12.1\n');
}
if (deb_check(prefix: 'samba-doc', release: '3.0', reference: '2.2.3a-12.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package samba-doc is vulnerable in Debian 3.0.\nUpgrade to samba-doc_2.2.3a-12.1\n');
}
if (deb_check(prefix: 'smbclient', release: '3.0', reference: '2.2.3a-12.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package smbclient is vulnerable in Debian 3.0.\nUpgrade to smbclient_2.2.3a-12.1\n');
}
if (deb_check(prefix: 'smbfs', release: '3.0', reference: '2.2.3a-12.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package smbfs is vulnerable in Debian 3.0.\nUpgrade to smbfs_2.2.3a-12.1\n');
}
if (deb_check(prefix: 'swat', release: '3.0', reference: '2.2.3a-12.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package swat is vulnerable in Debian 3.0.\nUpgrade to swat_2.2.3a-12.1\n');
}
if (deb_check(prefix: 'winbind', release: '3.0', reference: '2.2.3a-12.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package winbind is vulnerable in Debian 3.0.\nUpgrade to winbind_2.2.3a-12.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
