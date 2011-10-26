# This script was automatically generated from the dsa-136
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The OpenSSL development team has announced that a security audit by A.L.
Digital Ltd and The Bunker, under the DARPA CHATS program, has revealed
remotely exploitable buffer overflow conditions in the OpenSSL code.
Additionally, the ASN1 parser in OpenSSL has a potential DoS attack
independently discovered by Adi Stav and James Yonan.
CVE-2002-0655 references overflows in buffers used to hold ASCII
representations of integers on 64 bit platforms. CVE-2002-0656
references buffer overflows in the SSL2 server implementation (by
sending an invalid key to the server) and the SSL3 client implementation
(by sending a large session id to the client). The SSL2 issue was also
noticed by Neohapsis, who have privately demonstrated exploit code for
this issue. CVE-2002-0659 references the ASN1 parser DoS issue.
These vulnerabilities have been addressed for Debian 3.0 (woody) in
openssl094_0.9.4-6.woody.2, openssl095_0.9.5a-6.woody.1 and
openssl_0.9.6c-2.woody.1.
These vulnerabilities are also present in Debian 2.2 (potato). Fixed
packages are available in openssl094_0.9.4-6.potato.2 and
openssl_0.9.6c-0.potato.4.
A worm is actively exploiting this issue on internet-attached hosts;
we recommend you upgrade your OpenSSL as soon as possible. Note that you
must restart any daemons using SSL. (E.g., ssh or ssl-enabled apache.)
If you are uncertain which programs are using SSL you may choose to
reboot to ensure that all running daemons are using the new libraries.


Solution : http://www.debian.org/security/2002/dsa-136
Risk factor : High';

if (description) {
 script_id(14973);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "136");
 script_cve_id("CVE-2002-0655", "CVE-2002-0656", "CVE-2002-0657", "CVE-2002-0659");
 script_bugtraq_id(5353, 5361, 5362, 5363, 5364, 5366);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA136] DSA-136-1 openssl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-136-1 openssl");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libssl-dev', release: '2.2', reference: '0.9.6c-0.potato.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libssl-dev is vulnerable in Debian 2.2.\nUpgrade to libssl-dev_0.9.6c-0.potato.4\n');
}
if (deb_check(prefix: 'libssl0.9.6', release: '2.2', reference: '0.9.6c-0.potato.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libssl0.9.6 is vulnerable in Debian 2.2.\nUpgrade to libssl0.9.6_0.9.6c-0.potato.4\n');
}
if (deb_check(prefix: 'libssl09', release: '2.2', reference: '0.9.4-6.potato.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libssl09 is vulnerable in Debian 2.2.\nUpgrade to libssl09_0.9.4-6.potato.2\n');
}
if (deb_check(prefix: 'openssl', release: '2.2', reference: '0.9.6c-0.potato.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openssl is vulnerable in Debian 2.2.\nUpgrade to openssl_0.9.6c-0.potato.4\n');
}
if (deb_check(prefix: 'ssleay', release: '2.2', reference: '0.9.6c-0.potato.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ssleay is vulnerable in Debian 2.2.\nUpgrade to ssleay_0.9.6c-0.potato.3\n');
}
if (deb_check(prefix: 'libssl-dev', release: '3.0', reference: '0.9.6c-2.woody.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libssl-dev is vulnerable in Debian 3.0.\nUpgrade to libssl-dev_0.9.6c-2.woody.1\n');
}
if (deb_check(prefix: 'libssl0.9.6', release: '3.0', reference: '0.9.6c-2.woody.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libssl0.9.6 is vulnerable in Debian 3.0.\nUpgrade to libssl0.9.6_0.9.6c-2.woody.1\n');
}
if (deb_check(prefix: 'libssl09', release: '3.0', reference: '0.9.4-6.woody.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libssl09 is vulnerable in Debian 3.0.\nUpgrade to libssl09_0.9.4-6.woody.1\n');
}
if (deb_check(prefix: 'libssl095a', release: '3.0', reference: '0.9.5a-6.woody.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libssl095a is vulnerable in Debian 3.0.\nUpgrade to libssl095a_0.9.5a-6.woody.1\n');
}
if (deb_check(prefix: 'openssl', release: '3.0', reference: '0.9.6c-2.woody.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openssl is vulnerable in Debian 3.0.\nUpgrade to openssl_0.9.6c-2.woody.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
