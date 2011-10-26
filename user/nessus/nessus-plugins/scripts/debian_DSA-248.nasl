# This script was automatically generated from the dsa-248
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Ulf Härnhammar discovered two problems in hypermail, a program to
create HTML archives of mailing lists.
An attacker could craft a long filename for an attachment that would
overflow two buffers when a certain option for interactive use was
given, opening the possibility to inject arbitrary code.  This code
would then be executed under the user id hypermail runs as, mostly as
a local user.  Automatic and silent use of hypermail does not seem to
be affected.
The CGI program mail, which is not installed by the Debian package,
does a reverse look-up of the user\'s IP number and copies the
resulting hostname into a fixed-size buffer.  A specially crafted DNS
reply could overflow this buffer, opening the program to an exploit.
For the stable distribution (woody) this problem has been fixed in
version 2.1.3-2.0.
For the old stable distribution (potato) this problem has been fixed
in version 2.0b25-1.1.
For the unstable distribution (sid) this problem has been fixed
in version 2.1.6-1.
We recommend that you upgrade your hypermail packages.


Solution : http://www.debian.org/security/2003/dsa-248
Risk factor : High';

if (description) {
 script_id(15085);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "248");
 script_cve_id("CVE-2003-0057");
 script_bugtraq_id(6689, 6690);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA248] DSA-248-1 hypermail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-248-1 hypermail");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'hypermail', release: '2.2', reference: '2.0b25-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hypermail is vulnerable in Debian 2.2.\nUpgrade to hypermail_2.0b25-1.1\n');
}
if (deb_check(prefix: 'hypermail', release: '3.0', reference: '2.1.3-2.0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hypermail is vulnerable in Debian 3.0.\nUpgrade to hypermail_2.1.3-2.0\n');
}
if (deb_check(prefix: 'hypermail', release: '3.1', reference: '2.1.6-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hypermail is vulnerable in Debian 3.1.\nUpgrade to hypermail_2.1.6-1\n');
}
if (deb_check(prefix: 'hypermail', release: '2.2', reference: '2.0b25-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hypermail is vulnerable in Debian potato.\nUpgrade to hypermail_2.0b25-1.1\n');
}
if (deb_check(prefix: 'hypermail', release: '3.0', reference: '2.1.3-2.0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hypermail is vulnerable in Debian woody.\nUpgrade to hypermail_2.1.3-2.0\n');
}
if (w) { security_hole(port: 0, data: desc); }
