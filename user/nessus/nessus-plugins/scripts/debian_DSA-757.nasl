# This script was automatically generated from the dsa-757
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Daniel Wachdorf reported two problems in the MIT krb5 distribution used
for network authentication. First, the KDC program from the krb5-kdc
package can corrupt the heap by trying to free memory which has already
been freed on receipt of a certain TCP connection. This vulnerability
can cause the KDC to crash, leading to a denial of service.
[CVE-2005-1174] Second, under certain rare circumstances this type of
request can lead to a buffer overflow and remote code execution.
[CVE-2005-1175] 
Additionally, Magnus Hagander reported another problem in which the
krb5_recvauth function can in certain circumstances free previously
freed memory, potentially leading to the execution of remote code.
[CVE-2005-1689] 
All of these vulnerabilities are believed difficult to exploit, and no
exploits have yet been discovered.
For the old stable distribution (woody), these problems have been fixed
in version 1.2.4-5woody10. Note that woody\'s KDC does not have TCP
support and is not vulnerable to CVE-2005-1174.
For the stable distribution (sarge), these problems have been fixed in
version 1.3.6-2sarge2.
For the unstable distribution (sid), these problems have been fixed in
version 1.3.6-4.
We recommend that you upgrade your krb5 package.


Solution : http://www.debian.org/security/2005/dsa-757
Risk factor : High';

if (description) {
 script_id(19219);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2005-t-0027");
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "757");
 script_cve_id("CVE-2005-1174", "CVE-2005-1175", "CVE-2005-1689");
 script_xref(name: "CERT", value: "259798");
 script_xref(name: "CERT", value: "623332");
 script_xref(name: "CERT", value: "885830");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA757] DSA-757-1 krb5");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-757-1 krb5");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'krb5', release: '', reference: '1.3.6-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5 is vulnerable in Debian .\nUpgrade to krb5_1.3.6-4\n');
}
if (deb_check(prefix: 'krb5-admin-server', release: '3.0', reference: '1.2.4-5woody10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-admin-server is vulnerable in Debian 3.0.\nUpgrade to krb5-admin-server_1.2.4-5woody10\n');
}
if (deb_check(prefix: 'krb5-clients', release: '3.0', reference: '1.2.4-5woody10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-clients is vulnerable in Debian 3.0.\nUpgrade to krb5-clients_1.2.4-5woody10\n');
}
if (deb_check(prefix: 'krb5-doc', release: '3.0', reference: '1.2.4-5woody10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-doc is vulnerable in Debian 3.0.\nUpgrade to krb5-doc_1.2.4-5woody10\n');
}
if (deb_check(prefix: 'krb5-ftpd', release: '3.0', reference: '1.2.4-5woody10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-ftpd is vulnerable in Debian 3.0.\nUpgrade to krb5-ftpd_1.2.4-5woody10\n');
}
if (deb_check(prefix: 'krb5-kdc', release: '3.0', reference: '1.2.4-5woody10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-kdc is vulnerable in Debian 3.0.\nUpgrade to krb5-kdc_1.2.4-5woody10\n');
}
if (deb_check(prefix: 'krb5-rsh-server', release: '3.0', reference: '1.2.4-5woody10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-rsh-server is vulnerable in Debian 3.0.\nUpgrade to krb5-rsh-server_1.2.4-5woody10\n');
}
if (deb_check(prefix: 'krb5-telnetd', release: '3.0', reference: '1.2.4-5woody10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-telnetd is vulnerable in Debian 3.0.\nUpgrade to krb5-telnetd_1.2.4-5woody10\n');
}
if (deb_check(prefix: 'krb5-user', release: '3.0', reference: '1.2.4-5woody10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-user is vulnerable in Debian 3.0.\nUpgrade to krb5-user_1.2.4-5woody10\n');
}
if (deb_check(prefix: 'libkadm55', release: '3.0', reference: '1.2.4-5woody10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkadm55 is vulnerable in Debian 3.0.\nUpgrade to libkadm55_1.2.4-5woody10\n');
}
if (deb_check(prefix: 'libkrb5-dev', release: '3.0', reference: '1.2.4-5woody10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkrb5-dev is vulnerable in Debian 3.0.\nUpgrade to libkrb5-dev_1.2.4-5woody10\n');
}
if (deb_check(prefix: 'libkrb53', release: '3.0', reference: '1.2.4-5woody10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkrb53 is vulnerable in Debian 3.0.\nUpgrade to libkrb53_1.2.4-5woody10\n');
}
if (deb_check(prefix: 'krb5-admin-server', release: '3.1', reference: '1.3.6-2sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-admin-server is vulnerable in Debian 3.1.\nUpgrade to krb5-admin-server_1.3.6-2sarge2\n');
}
if (deb_check(prefix: 'krb5-clients', release: '3.1', reference: '1.3.6-2sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-clients is vulnerable in Debian 3.1.\nUpgrade to krb5-clients_1.3.6-2sarge2\n');
}
if (deb_check(prefix: 'krb5-doc', release: '3.1', reference: '1.3.6-2sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-doc is vulnerable in Debian 3.1.\nUpgrade to krb5-doc_1.3.6-2sarge2\n');
}
if (deb_check(prefix: 'krb5-ftpd', release: '3.1', reference: '1.3.6-2sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-ftpd is vulnerable in Debian 3.1.\nUpgrade to krb5-ftpd_1.3.6-2sarge2\n');
}
if (deb_check(prefix: 'krb5-kdc', release: '3.1', reference: '1.3.6-2sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-kdc is vulnerable in Debian 3.1.\nUpgrade to krb5-kdc_1.3.6-2sarge2\n');
}
if (deb_check(prefix: 'krb5-rsh-server', release: '3.1', reference: '1.3.6-2sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-rsh-server is vulnerable in Debian 3.1.\nUpgrade to krb5-rsh-server_1.3.6-2sarge2\n');
}
if (deb_check(prefix: 'krb5-telnetd', release: '3.1', reference: '1.3.6-2sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-telnetd is vulnerable in Debian 3.1.\nUpgrade to krb5-telnetd_1.3.6-2sarge2\n');
}
if (deb_check(prefix: 'krb5-user', release: '3.1', reference: '1.3.6-2sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-user is vulnerable in Debian 3.1.\nUpgrade to krb5-user_1.3.6-2sarge2\n');
}
if (deb_check(prefix: 'libkadm55', release: '3.1', reference: '1.3.6-2sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkadm55 is vulnerable in Debian 3.1.\nUpgrade to libkadm55_1.3.6-2sarge2\n');
}
if (deb_check(prefix: 'libkrb5-dev', release: '3.1', reference: '1.3.6-2sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkrb5-dev is vulnerable in Debian 3.1.\nUpgrade to libkrb5-dev_1.3.6-2sarge2\n');
}
if (deb_check(prefix: 'libkrb53', release: '3.1', reference: '1.3.6-2sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkrb53 is vulnerable in Debian 3.1.\nUpgrade to libkrb53_1.3.6-2sarge2\n');
}
if (deb_check(prefix: 'krb5', release: '3.1', reference: '1.3.6-2sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5 is vulnerable in Debian sarge.\nUpgrade to krb5_1.3.6-2sarge2\n');
}
if (deb_check(prefix: 'krb5', release: '3.0', reference: '1.2.4-5woody10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5 is vulnerable in Debian woody.\nUpgrade to krb5_1.2.4-5woody10\n');
}
if (w) { security_hole(port: 0, data: desc); }
