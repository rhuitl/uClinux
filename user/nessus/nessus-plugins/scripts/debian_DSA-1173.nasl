# This script was automatically generated from the dsa-1173
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Daniel Bleichenbacher discovered a flaw in the OpenSSL cryptographic package
that could allow an attacker to generate a forged signature that OpenSSL
will accept as valid.
For the stable distribution (sarge) this problem has been fixed in
version 0.9.7e-3sarge2.
For the unstable distribution (sid) this problem has been fixed in
version 0.9.8b-3.
We recommend that you upgrade your openssl packages.  Note that services
linking against the openssl shared libraries will need to be restarted.
Common examples of such services include most Mail Transport Agents, SSH
servers, and web servers.


Solution : http://www.debian.org/security/2006/dsa-1173
Risk factor : High';

if (description) {
 script_id(22715);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1173");
 script_cve_id("CVE-2006-4339");
 script_bugtraq_id(19849);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1173] DSA-1173-1 openssl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1173-1 openssl");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'openssl', release: '', reference: '0.9.8b-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openssl is vulnerable in Debian .\nUpgrade to openssl_0.9.8b-3\n');
}
if (deb_check(prefix: 'libssl-dev', release: '3.1', reference: '0.9.7e-3sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libssl-dev is vulnerable in Debian 3.1.\nUpgrade to libssl-dev_0.9.7e-3sarge2\n');
}
if (deb_check(prefix: 'libssl0.9.7', release: '3.1', reference: '0.9.7e-3sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libssl0.9.7 is vulnerable in Debian 3.1.\nUpgrade to libssl0.9.7_0.9.7e-3sarge2\n');
}
if (deb_check(prefix: 'openssl', release: '3.1', reference: '0.9.7e-3sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openssl is vulnerable in Debian 3.1.\nUpgrade to openssl_0.9.7e-3sarge2\n');
}
if (deb_check(prefix: 'openssl', release: '3.1', reference: '0.9.7e-3sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openssl is vulnerable in Debian sarge.\nUpgrade to openssl_0.9.7e-3sarge2\n');
}
if (w) { security_hole(port: 0, data: desc); }
