# This script was automatically generated from the dsa-690
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Bastian Blank discovered a vulnerability in bsmtpd, a batched SMTP mailer for
sendmail and postfix.  Unsanitised addresses can cause the execution
of arbitrary commands during alleged mail delivery.
For the stable distribution (woody) this problem has been fixed in
version 2.3pl8b-12woody1.
For the unstable distribution (sid) this problem has been fixed in
version 2.3pl8b-16.
We recommend that you upgrade your bsmtpd package.


Solution : http://www.debian.org/security/2005/dsa-690
Risk factor : High';

if (description) {
 script_id(17232);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "690");
 script_cve_id("CVE-2005-0107");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA690] DSA-690-1 bsmtpd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-690-1 bsmtpd");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'bsmtpd', release: '3.0', reference: '2.3pl8b-12woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bsmtpd is vulnerable in Debian 3.0.\nUpgrade to bsmtpd_2.3pl8b-12woody1\n');
}
if (deb_check(prefix: 'bsmtpd', release: '3.1', reference: '2.3pl8b-16')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bsmtpd is vulnerable in Debian 3.1.\nUpgrade to bsmtpd_2.3pl8b-16\n');
}
if (deb_check(prefix: 'bsmtpd', release: '3.0', reference: '2.3pl8b-12woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bsmtpd is vulnerable in Debian woody.\nUpgrade to bsmtpd_2.3pl8b-12woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
