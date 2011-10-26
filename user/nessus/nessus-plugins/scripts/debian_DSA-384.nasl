# This script was automatically generated from the dsa-384
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Two vulnerabilities were reported in sendmail.
   A "potential buffer overflow in ruleset parsing" for Sendmail
   8.12.9, when using the nonstandard rulesets (1) recipient (2),
   final, or (3) mailer-specific envelope recipients, has unknown
   consequences.
  The prescan function in Sendmail 8.12.9 allows remote attackers to
  execute arbitrary code via buffer overflow attacks, as demonstrated
  using the parseaddr function in parseaddr.c.
For the stable distribution (woody) these problems have been fixed in
sendmail version 8.12.3-6.6 and sendmail-wide version
8.12.3+3.5Wbeta-5.5.
For the unstable distribution (sid) these problems have been fixed in
sendmail version 8.12.10-1.
We recommend that you update your sendmail package.


Solution : http://www.debian.org/security/2003/dsa-384
Risk factor : High';

if (description) {
 script_id(15221);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-b-0005");
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "384");
 script_cve_id("CVE-2003-0681", "CVE-2003-0694");
 script_bugtraq_id(8641, 8649);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA384] DSA-384-1 sendmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-384-1 sendmail");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libmilter-dev', release: '3.0', reference: '8.12.3-6.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmilter-dev is vulnerable in Debian 3.0.\nUpgrade to libmilter-dev_8.12.3-6.6\n');
}
if (deb_check(prefix: 'sendmail', release: '3.0', reference: '8.12.3-6.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sendmail is vulnerable in Debian 3.0.\nUpgrade to sendmail_8.12.3-6.6\n');
}
if (deb_check(prefix: 'sendmail-doc', release: '3.0', reference: '8.12.3-6.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sendmail-doc is vulnerable in Debian 3.0.\nUpgrade to sendmail-doc_8.12.3-6.6\n');
}
if (deb_check(prefix: 'sendmail-wide', release: '3.0', reference: '8.12.3+3.5Wbeta-5.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sendmail-wide is vulnerable in Debian 3.0.\nUpgrade to sendmail-wide_8.12.3+3.5Wbeta-5.5\n');
}
if (deb_check(prefix: 'sendmail', release: '3.1', reference: '8.12.10-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sendmail is vulnerable in Debian 3.1.\nUpgrade to sendmail_8.12.10-1\n');
}
if (deb_check(prefix: 'sendmail', release: '3.0', reference: '8.12.3-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sendmail is vulnerable in Debian woody.\nUpgrade to sendmail_8.12.3-6\n');
}
if (w) { security_hole(port: 0, data: desc); }
