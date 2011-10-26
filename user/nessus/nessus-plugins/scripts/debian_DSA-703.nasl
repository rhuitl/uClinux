# This script was automatically generated from the dsa-703
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several problems have been discovered in telnet clients that could be
exploited by malicious daemons the client connects to.  The Common
Vulnerabilities and Exposures project identifies the following
problems:
    Gaël Delalleau discovered a buffer overflow in the env_opt_add()
    function that allow a remote attacker to execute arbitrary code.
    Gaël Delalleau discovered a buffer overflow in the handling of the
    LINEMODE suboptions in telnet clients.  This can lead to the
    execution of arbitrary code when connected to a malicious server.
For the stable distribution (woody) these problems have been fixed in
version 1.2.4-5woody8.
For the unstable distribution (sid) these problems have been fixed in
version 1.3.6-1.
We recommend that you upgrade your krb5 package.


Solution : http://www.debian.org/security/2005/dsa-703
Risk factor : High';

if (description) {
 script_id(17674);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "703");
 script_cve_id("CVE-2005-0468", "CVE-2005-0469");
 script_xref(name: "CERT", value: "291924");
 script_xref(name: "CERT", value: "341908");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA703] DSA-703-1 krb5");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-703-1 krb5");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'krb5-admin-server', release: '3.0', reference: '1.2.4-5woody8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-admin-server is vulnerable in Debian 3.0.\nUpgrade to krb5-admin-server_1.2.4-5woody8\n');
}
if (deb_check(prefix: 'krb5-clients', release: '3.0', reference: '1.2.4-5woody8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-clients is vulnerable in Debian 3.0.\nUpgrade to krb5-clients_1.2.4-5woody8\n');
}
if (deb_check(prefix: 'krb5-doc', release: '3.0', reference: '1.2.4-5woody8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-doc is vulnerable in Debian 3.0.\nUpgrade to krb5-doc_1.2.4-5woody8\n');
}
if (deb_check(prefix: 'krb5-ftpd', release: '3.0', reference: '1.2.4-5woody8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-ftpd is vulnerable in Debian 3.0.\nUpgrade to krb5-ftpd_1.2.4-5woody8\n');
}
if (deb_check(prefix: 'krb5-kdc', release: '3.0', reference: '1.2.4-5woody8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-kdc is vulnerable in Debian 3.0.\nUpgrade to krb5-kdc_1.2.4-5woody8\n');
}
if (deb_check(prefix: 'krb5-rsh-server', release: '3.0', reference: '1.2.4-5woody8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-rsh-server is vulnerable in Debian 3.0.\nUpgrade to krb5-rsh-server_1.2.4-5woody8\n');
}
if (deb_check(prefix: 'krb5-telnetd', release: '3.0', reference: '1.2.4-5woody8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-telnetd is vulnerable in Debian 3.0.\nUpgrade to krb5-telnetd_1.2.4-5woody8\n');
}
if (deb_check(prefix: 'krb5-user', release: '3.0', reference: '1.2.4-5woody8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-user is vulnerable in Debian 3.0.\nUpgrade to krb5-user_1.2.4-5woody8\n');
}
if (deb_check(prefix: 'libkadm55', release: '3.0', reference: '1.2.4-5woody8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkadm55 is vulnerable in Debian 3.0.\nUpgrade to libkadm55_1.2.4-5woody8\n');
}
if (deb_check(prefix: 'libkrb5-dev', release: '3.0', reference: '1.2.4-5woody8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkrb5-dev is vulnerable in Debian 3.0.\nUpgrade to libkrb5-dev_1.2.4-5woody8\n');
}
if (deb_check(prefix: 'libkrb53', release: '3.0', reference: '1.2.4-5woody8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkrb53 is vulnerable in Debian 3.0.\nUpgrade to libkrb53_1.2.4-5woody8\n');
}
if (deb_check(prefix: 'krb5', release: '3.1', reference: '1.3.6-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5 is vulnerable in Debian 3.1.\nUpgrade to krb5_1.3.6-1\n');
}
if (deb_check(prefix: 'krb5', release: '3.0', reference: '1.2.4-5woody8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5 is vulnerable in Debian woody.\nUpgrade to krb5_1.2.4-5woody8\n');
}
if (w) { security_hole(port: 0, data: desc); }
