# This script was automatically generated from the dsa-257
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Mark Dowd of ISS X-Force found a bug in the header parsing routines
of sendmail: it could overflow a buffer overflow when encountering
addresses with very long comments. Since sendmail also parses headers
when forwarding emails this vulnerability can hit mail-servers which do
not deliver the email as well.
This has been fixed in upstream release 8.12.8, version 8.12.3-5 of
the package for Debian GNU/Linux 3.0/woody and version 8.9.3-25 of the
package for Debian GNU/Linux 2.2/potato.
DSA-257-2: Updated sendmail-wide packages are available in package
version 8.9.3+3.2W-24 for Debian 2.2 (potato) and
version 8.12.3+3.5Wbeta-5.2 for Debian 3.0 (woody).


Solution : http://www.debian.org/security/2003/dsa-257
Risk factor : High';

if (description) {
 script_id(15094);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "257");
 script_cve_id("CVE-2002-1337");
 script_xref(name: "CERT", value: "398025");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA257] DSA-257-1 sendmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-257-1 sendmail");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'sendmail', release: '2.2', reference: '8.9.3-25')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sendmail is vulnerable in Debian 2.2.\nUpgrade to sendmail_8.9.3-25\n');
}
if (deb_check(prefix: 'sendmail-wide', release: '2.2', reference: '8.9.3+3.2W-24')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sendmail-wide is vulnerable in Debian 2.2.\nUpgrade to sendmail-wide_8.9.3+3.2W-24\n');
}
if (deb_check(prefix: 'libmilter-dev', release: '3.0', reference: '8.12.3-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmilter-dev is vulnerable in Debian 3.0.\nUpgrade to libmilter-dev_8.12.3-5\n');
}
if (deb_check(prefix: 'sendmail', release: '3.0', reference: '8.12.3-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sendmail is vulnerable in Debian 3.0.\nUpgrade to sendmail_8.12.3-5\n');
}
if (deb_check(prefix: 'sendmail-doc', release: '3.0', reference: '8.12.3-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sendmail-doc is vulnerable in Debian 3.0.\nUpgrade to sendmail-doc_8.12.3-5\n');
}
if (deb_check(prefix: 'sendmail-wide', release: '3.0', reference: '8.12.3+3.5Wbeta-5.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sendmail-wide is vulnerable in Debian 3.0.\nUpgrade to sendmail-wide_8.12.3+3.5Wbeta-5.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
