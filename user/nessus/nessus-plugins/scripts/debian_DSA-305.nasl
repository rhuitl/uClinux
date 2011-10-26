# This script was automatically generated from the dsa-305
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Paul Szabo discovered bugs in three scripts included in the sendmail
package where temporary files were created insecurely (expn,
checksendmail and doublebounce.pl).  These bugs could allow an
attacker to gain the privileges of a user invoking the script
(including root).
For the stable distribution (woody) these problems have been fixed in
version 8.12.3-6.4.
For the old stable distribution (potato) these problems have been fixed
in version 8.9.3-26.1.
For the unstable distribution (sid) these problems have been fixed in
version 8.12.9-2.
We recommend that you update your sendmail package.


Solution : http://www.debian.org/security/2003/dsa-305
Risk factor : High';

if (description) {
 script_id(15142);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "305");
 script_cve_id("CVE-2003-0308");
 script_bugtraq_id(7614);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA305] DSA-305-1 sendmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-305-1 sendmail");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'sendmail', release: '2.2', reference: '8.9.3-26.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sendmail is vulnerable in Debian 2.2.\nUpgrade to sendmail_8.9.3-26.1\n');
}
if (deb_check(prefix: 'libmilter-dev', release: '3.0', reference: '8.12.3-6.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmilter-dev is vulnerable in Debian 3.0.\nUpgrade to libmilter-dev_8.12.3-6.4\n');
}
if (deb_check(prefix: 'sendmail', release: '3.0', reference: '8.12.9-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sendmail is vulnerable in Debian 3.0.\nUpgrade to sendmail_8.12.9-2\n');
}
if (deb_check(prefix: 'sendmail-doc', release: '3.0', reference: '8.12.3-6.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sendmail-doc is vulnerable in Debian 3.0.\nUpgrade to sendmail-doc_8.12.3-6.4\n');
}
if (deb_check(prefix: 'sendmail', release: '2.2', reference: '8.9.3-26.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sendmail is vulnerable in Debian potato.\nUpgrade to sendmail_8.9.3-26.1\n');
}
if (deb_check(prefix: 'sendmail', release: '3.0', reference: '8.12.3-6.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sendmail is vulnerable in Debian woody.\nUpgrade to sendmail_8.12.3-6.4\n');
}
if (w) { security_hole(port: 0, data: desc); }
