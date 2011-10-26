# This script was automatically generated from the dsa-1164
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A programming error has been discovered in sendmail, an alternative
mail transport agent for Debian, that could allow a remote attacker to
crash the sendmail process by sending a specially crafted email
message.
Please note that in order to install this update you also need
libsasl2 library from proposed updates as outlined in DSA 1155-2.
For the stable distribution (sarge) this problem has been fixed in
version 8.13.3-3sarge3.
For the unstable distribution (sid) this problem has been fixed in
version 8.13.8-1.
We recommend that you upgrade your sendmail package.


Solution : http://www.debian.org/security/2006/dsa-1164
Risk factor : High';

if (description) {
 script_id(22706);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1164");
 script_cve_id("CVE-2006-4434");
 script_bugtraq_id(19714);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1164] DSA-1164-1 sendmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1164-1 sendmail");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'sendmail', release: '', reference: '8.13.8-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sendmail is vulnerable in Debian .\nUpgrade to sendmail_8.13.8-1\n');
}
if (deb_check(prefix: 'libmilter-dev', release: '3.1', reference: '8.13.4-3sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmilter-dev is vulnerable in Debian 3.1.\nUpgrade to libmilter-dev_8.13.4-3sarge3\n');
}
if (deb_check(prefix: 'libmilter0', release: '3.1', reference: '8.13.4-3sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmilter0 is vulnerable in Debian 3.1.\nUpgrade to libmilter0_8.13.4-3sarge3\n');
}
if (deb_check(prefix: 'rmail', release: '3.1', reference: '8.13.4-3sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package rmail is vulnerable in Debian 3.1.\nUpgrade to rmail_8.13.4-3sarge3\n');
}
if (deb_check(prefix: 'sendmail', release: '3.1', reference: '8.13.4-3sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sendmail is vulnerable in Debian 3.1.\nUpgrade to sendmail_8.13.4-3sarge3\n');
}
if (deb_check(prefix: 'sendmail-base', release: '3.1', reference: '8.13.4-3sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sendmail-base is vulnerable in Debian 3.1.\nUpgrade to sendmail-base_8.13.4-3sarge3\n');
}
if (deb_check(prefix: 'sendmail-bin', release: '3.1', reference: '8.13.4-3sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sendmail-bin is vulnerable in Debian 3.1.\nUpgrade to sendmail-bin_8.13.4-3sarge3\n');
}
if (deb_check(prefix: 'sendmail-cf', release: '3.1', reference: '8.13.4-3sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sendmail-cf is vulnerable in Debian 3.1.\nUpgrade to sendmail-cf_8.13.4-3sarge3\n');
}
if (deb_check(prefix: 'sendmail-doc', release: '3.1', reference: '8.13.4-3sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sendmail-doc is vulnerable in Debian 3.1.\nUpgrade to sendmail-doc_8.13.4-3sarge3\n');
}
if (deb_check(prefix: 'sensible-mda', release: '3.1', reference: '8.13.4-3sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sensible-mda is vulnerable in Debian 3.1.\nUpgrade to sensible-mda_8.13.4-3sarge3\n');
}
if (deb_check(prefix: 'sendmail', release: '3.1', reference: '8.13.3-3sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sendmail is vulnerable in Debian sarge.\nUpgrade to sendmail_8.13.3-3sarge3\n');
}
if (w) { security_hole(port: 0, data: desc); }
