# This script was automatically generated from the dsa-554
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Hugo Espuny discovered a problem in sendmail, a commonly used program
to deliver electronic mail.  When installing "sasl-bin" to use sasl in
connection with sendmail, the sendmail configuration script use fixed
user/pass information to initialise the sasl database.  Any spammer
with Debian systems knowledge could utilise such a sendmail
installation to relay spam.
For the stable distribution (woody) this problem has been fixed in
version 8.12.3-7.1.
For the unstable distribution (sid) this problem has been fixed in
version 8.13.1-13.
We recommend that you upgrade your sendmail package.


Solution : http://www.debian.org/security/2004/dsa-554
Risk factor : High';

if (description) {
 script_id(15391);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "554");
 script_cve_id("CVE-2004-0833");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA554] DSA-554-1 sendmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-554-1 sendmail");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libmilter-dev', release: '3.0', reference: '8.12.3-7.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmilter-dev is vulnerable in Debian 3.0.\nUpgrade to libmilter-dev_8.12.3-7.1\n');
}
if (deb_check(prefix: 'sendmail', release: '3.0', reference: '8.12.3-7.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sendmail is vulnerable in Debian 3.0.\nUpgrade to sendmail_8.12.3-7.1\n');
}
if (deb_check(prefix: 'sendmail-doc', release: '3.0', reference: '8.12.3-7.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sendmail-doc is vulnerable in Debian 3.0.\nUpgrade to sendmail-doc_8.12.3-7.1\n');
}
if (deb_check(prefix: 'sendmail', release: '3.1', reference: '8.13.1-13')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sendmail is vulnerable in Debian 3.1.\nUpgrade to sendmail_8.13.1-13\n');
}
if (deb_check(prefix: 'sendmail', release: '3.0', reference: '8.12.3-7.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sendmail is vulnerable in Debian woody.\nUpgrade to sendmail_8.12.3-7.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
