# This script was automatically generated from the dsa-266
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several vulnerabilities have been discovered in krb5, an
implementation of MIT Kerberos.
   Kerberos version 5 does not contain this cryptographic
   vulnerability.  Sites are not vulnerable if they have Kerberos v4
   completely disabled, including the disabling of any krb5 to krb4
   translation services.

This version of the krb5 package changes the default behavior and
disallows cross-realm authentication for Kerberos version 4.  Because
of the fundamental nature of the problem, cross-realm authentication
in Kerberos version 4 cannot be made secure and sites should avoid its
use.  A new option (-X) is provided to the krb5kdc and krb524d
commands to re-enable version 4 cross-realm authentication for those
sites that must use this functionality but desire the other security
fixes.

For the stable distribution (woody) this problem has been
fixed in version 1.2.4-5woody4.
The old stable distribution (potato) does not contain krb5 packages.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you upgrade your krb5 package.


Solution : http://www.debian.org/security/2003/dsa-266
Risk factor : High';

if (description) {
 script_id(15103);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-t-0007");
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "266");
 script_cve_id("CVE-2003-0028", "CVE-2003-0072", "CVE-2003-0082", "CVE-2003-0138", "CVE-2003-0139");
 script_xref(name: "CERT", value: "442569");
 script_xref(name: "CERT", value: "516825");
 script_xref(name: "CERT", value: "623217");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA266] DSA-266-1 krb5");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-266-1 krb5");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'krb5-admin-server', release: '3.0', reference: '1.2.4-5woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-admin-server is vulnerable in Debian 3.0.\nUpgrade to krb5-admin-server_1.2.4-5woody4\n');
}
if (deb_check(prefix: 'krb5-clients', release: '3.0', reference: '1.2.4-5woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-clients is vulnerable in Debian 3.0.\nUpgrade to krb5-clients_1.2.4-5woody4\n');
}
if (deb_check(prefix: 'krb5-doc', release: '3.0', reference: '1.2.4-5woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-doc is vulnerable in Debian 3.0.\nUpgrade to krb5-doc_1.2.4-5woody4\n');
}
if (deb_check(prefix: 'krb5-ftpd', release: '3.0', reference: '1.2.4-5woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-ftpd is vulnerable in Debian 3.0.\nUpgrade to krb5-ftpd_1.2.4-5woody4\n');
}
if (deb_check(prefix: 'krb5-kdc', release: '3.0', reference: '1.2.4-5woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-kdc is vulnerable in Debian 3.0.\nUpgrade to krb5-kdc_1.2.4-5woody4\n');
}
if (deb_check(prefix: 'krb5-rsh-server', release: '3.0', reference: '1.2.4-5woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-rsh-server is vulnerable in Debian 3.0.\nUpgrade to krb5-rsh-server_1.2.4-5woody4\n');
}
if (deb_check(prefix: 'krb5-telnetd', release: '3.0', reference: '1.2.4-5woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-telnetd is vulnerable in Debian 3.0.\nUpgrade to krb5-telnetd_1.2.4-5woody4\n');
}
if (deb_check(prefix: 'krb5-user', release: '3.0', reference: '1.2.4-5woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-user is vulnerable in Debian 3.0.\nUpgrade to krb5-user_1.2.4-5woody4\n');
}
if (deb_check(prefix: 'libkadm55', release: '3.0', reference: '1.2.4-5woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkadm55 is vulnerable in Debian 3.0.\nUpgrade to libkadm55_1.2.4-5woody4\n');
}
if (deb_check(prefix: 'libkrb5-dev', release: '3.0', reference: '1.2.4-5woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkrb5-dev is vulnerable in Debian 3.0.\nUpgrade to libkrb5-dev_1.2.4-5woody4\n');
}
if (deb_check(prefix: 'libkrb53', release: '3.0', reference: '1.2.4-5woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkrb53 is vulnerable in Debian 3.0.\nUpgrade to libkrb53_1.2.4-5woody4\n');
}
if (deb_check(prefix: 'krb5', release: '3.0', reference: '1.2.4-5woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5 is vulnerable in Debian woody.\nUpgrade to krb5_1.2.4-5woody4\n');
}
if (w) { security_hole(port: 0, data: desc); }
