# This script was automatically generated from the dsa-1146
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
In certain application programs packaged in the MIT Kerberos 5 source
distribution, calls to setuid() and seteuid() are not always checked
for success and may fail with some PAM configurations.  A local
user could exploit one of these vulnerabilities to result in privilege
escalation.  No exploit code is known to exist at this time.
For the stable distribution (sarge) these problems have been fixed in
version 1.3.6-2sarge3.
For the unstable distribution (sid) these problems have been fixed in
version 1.4.3-9.
We recommend that you upgrade your krb5 packages.


Solution : http://www.debian.org/security/2006/dsa-1146
Risk factor : High';

if (description) {
 script_id(22688);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1146");
 script_cve_id("CVE-2006-3083", "CVE-2006-3084");
 script_xref(name: "CERT", value: "401660");
 script_xref(name: "CERT", value: "580124");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1146] DSA-1146-1 krb5");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1146-1 krb5");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'krb5', release: '', reference: '1.4.3-9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5 is vulnerable in Debian .\nUpgrade to krb5_1.4.3-9\n');
}
if (deb_check(prefix: 'krb5-admin-server', release: '3.1', reference: '1.3.6-2sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-admin-server is vulnerable in Debian 3.1.\nUpgrade to krb5-admin-server_1.3.6-2sarge3\n');
}
if (deb_check(prefix: 'krb5-clients', release: '3.1', reference: '1.3.6-2sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-clients is vulnerable in Debian 3.1.\nUpgrade to krb5-clients_1.3.6-2sarge3\n');
}
if (deb_check(prefix: 'krb5-doc', release: '3.1', reference: '1.3.6-2sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-doc is vulnerable in Debian 3.1.\nUpgrade to krb5-doc_1.3.6-2sarge3\n');
}
if (deb_check(prefix: 'krb5-ftpd', release: '3.1', reference: '1.3.6-2sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-ftpd is vulnerable in Debian 3.1.\nUpgrade to krb5-ftpd_1.3.6-2sarge3\n');
}
if (deb_check(prefix: 'krb5-kdc', release: '3.1', reference: '1.3.6-2sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-kdc is vulnerable in Debian 3.1.\nUpgrade to krb5-kdc_1.3.6-2sarge3\n');
}
if (deb_check(prefix: 'krb5-rsh-server', release: '3.1', reference: '1.3.6-2sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-rsh-server is vulnerable in Debian 3.1.\nUpgrade to krb5-rsh-server_1.3.6-2sarge3\n');
}
if (deb_check(prefix: 'krb5-telnetd', release: '3.1', reference: '1.3.6-2sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-telnetd is vulnerable in Debian 3.1.\nUpgrade to krb5-telnetd_1.3.6-2sarge3\n');
}
if (deb_check(prefix: 'krb5-user', release: '3.1', reference: '1.3.6-2sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-user is vulnerable in Debian 3.1.\nUpgrade to krb5-user_1.3.6-2sarge3\n');
}
if (deb_check(prefix: 'libkadm55', release: '3.1', reference: '1.3.6-2sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkadm55 is vulnerable in Debian 3.1.\nUpgrade to libkadm55_1.3.6-2sarge3\n');
}
if (deb_check(prefix: 'libkrb5-dev', release: '3.1', reference: '1.3.6-2sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkrb5-dev is vulnerable in Debian 3.1.\nUpgrade to libkrb5-dev_1.3.6-2sarge3\n');
}
if (deb_check(prefix: 'libkrb53', release: '3.1', reference: '1.3.6-2sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkrb53 is vulnerable in Debian 3.1.\nUpgrade to libkrb53_1.3.6-2sarge3\n');
}
if (deb_check(prefix: 'krb5', release: '3.1', reference: '1.3.6-2sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5 is vulnerable in Debian sarge.\nUpgrade to krb5_1.3.6-2sarge3\n');
}
if (w) { security_hole(port: 0, data: desc); }
