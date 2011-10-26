# This script was automatically generated from the dsa-060
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Wolfram Kleff found a problem in fetchmail: it would crash when
processing emails with extremely long headers. The problem was
a buffer overflow in the header parser which could be exploited.

This has been fixed in version 5.3.3-1.2, and we recommend that
you upgrade your fetchmail package immediately.



Solution : http://www.debian.org/security/2001/dsa-060
Risk factor : High';

if (description) {
 script_id(14897);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "060");
 script_cve_id("CVE-2001-0819");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA060] DSA-060-1 fetchmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-060-1 fetchmail");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'fetchmail', release: '2.2', reference: '5.3.3-1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fetchmail is vulnerable in Debian 2.2.\nUpgrade to fetchmail_5.3.3-1.2\n');
}
if (deb_check(prefix: 'fetchmailconf', release: '2.2', reference: '5.3.3-1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fetchmailconf is vulnerable in Debian 2.2.\nUpgrade to fetchmailconf_5.3.3-1.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
