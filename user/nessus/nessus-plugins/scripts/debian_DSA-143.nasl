# This script was automatically generated from the dsa-143
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
An integer overflow bug has been discovered in the RPC library used by
the Kerberos 5 administration system, which is derived from the SunRPC
library.  This bug could be exploited to gain unauthorized root access
to a KDC host.  It is believed that the attacker needs to be able to
authenticate to the kadmin daemon for this attack to be successful.
No exploits are known to exist yet.
This problem has been fixed in version 1.2.4-5woody1 for the current
stable distribution (woody) and in version 1.2.5-2 for the unstable
distribution (sid).  Debian 2.2 (potato) is not affected since it
doesn\'t contain krb5 packages.
We recommend that you upgrade your kerberos packages immediately.


Solution : http://www.debian.org/security/2002/dsa-143
Risk factor : High';

if (description) {
 script_id(14980);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-t-0015");
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "143");
 script_cve_id("CVE-2002-0391");
 script_bugtraq_id(5356);
 script_xref(name: "CERT", value: "192995");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA143] DSA-143-1 krb5");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-143-1 krb5");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'krb5-admin-server', release: '3.0', reference: '1.2.4-5woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-admin-server is vulnerable in Debian 3.0.\nUpgrade to krb5-admin-server_1.2.4-5woody1\n');
}
if (deb_check(prefix: 'krb5-clients', release: '3.0', reference: '1.2.4-5woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-clients is vulnerable in Debian 3.0.\nUpgrade to krb5-clients_1.2.4-5woody1\n');
}
if (deb_check(prefix: 'krb5-doc', release: '3.0', reference: '1.2.4-5woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-doc is vulnerable in Debian 3.0.\nUpgrade to krb5-doc_1.2.4-5woody1\n');
}
if (deb_check(prefix: 'krb5-ftpd', release: '3.0', reference: '1.2.4-5woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-ftpd is vulnerable in Debian 3.0.\nUpgrade to krb5-ftpd_1.2.4-5woody1\n');
}
if (deb_check(prefix: 'krb5-kdc', release: '3.0', reference: '1.2.4-5woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-kdc is vulnerable in Debian 3.0.\nUpgrade to krb5-kdc_1.2.4-5woody1\n');
}
if (deb_check(prefix: 'krb5-rsh-server', release: '3.0', reference: '1.2.4-5woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-rsh-server is vulnerable in Debian 3.0.\nUpgrade to krb5-rsh-server_1.2.4-5woody1\n');
}
if (deb_check(prefix: 'krb5-telnetd', release: '3.0', reference: '1.2.4-5woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-telnetd is vulnerable in Debian 3.0.\nUpgrade to krb5-telnetd_1.2.4-5woody1\n');
}
if (deb_check(prefix: 'krb5-user', release: '3.0', reference: '1.2.4-5woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-user is vulnerable in Debian 3.0.\nUpgrade to krb5-user_1.2.4-5woody1\n');
}
if (deb_check(prefix: 'libkadm55', release: '3.0', reference: '1.2.4-5woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkadm55 is vulnerable in Debian 3.0.\nUpgrade to libkadm55_1.2.4-5woody1\n');
}
if (deb_check(prefix: 'libkrb5-dev', release: '3.0', reference: '1.2.4-5woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkrb5-dev is vulnerable in Debian 3.0.\nUpgrade to libkrb5-dev_1.2.4-5woody1\n');
}
if (deb_check(prefix: 'libkrb53', release: '3.0', reference: '1.2.4-5woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkrb53 is vulnerable in Debian 3.0.\nUpgrade to libkrb53_1.2.4-5woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
