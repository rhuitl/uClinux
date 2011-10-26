# This script was automatically generated from the dsa-386
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The SuSE security team discovered during an audit a bug in
Mail::Mailer, a Perl module used for sending email, whereby
potentially untrusted input is passed to a program such as mailx,
which may interpret certain escape sequences as commands to be
executed.
This bug has been fixed by removing support for programs such as mailx
as a transport for sending mail.  Instead, alternative mechanisms are
used.
For the stable distribution (woody) this problem has been fixed in
version 1.44-1woody1.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you update your libmailtools-perl package.


Solution : http://www.debian.org/security/2003/dsa-386
Risk factor : High';

if (description) {
 script_id(15223);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "386");
 script_cve_id("CVE-2002-1271");
 script_bugtraq_id(6104);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA386] DSA-386-1 libmailtools-perl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-386-1 libmailtools-perl");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libmailtools-perl', release: '3.0', reference: '1.44-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmailtools-perl is vulnerable in Debian 3.0.\nUpgrade to libmailtools-perl_1.44-1woody2\n');
}
if (deb_check(prefix: 'mailtools', release: '3.0', reference: '1.44-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mailtools is vulnerable in Debian 3.0.\nUpgrade to mailtools_1.44-1woody2\n');
}
if (deb_check(prefix: 'libmailtools-perl', release: '3.0', reference: '1.44-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmailtools-perl is vulnerable in Debian woody.\nUpgrade to libmailtools-perl_1.44-1woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
