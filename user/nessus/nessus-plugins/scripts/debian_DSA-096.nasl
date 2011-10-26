# This script was automatically generated from the dsa-096
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Joost Pol found a buffer overflow in the address handling code of
mutt (a popular mail user agent). Even though this is a one byte
overflow this is exploitable.

This has been fixed upstream in version 1.2.5.1 and 1.3.25. The
relevant patch has been added to version 1.2.5-5 of the Debian
package.



Solution : http://www.debian.org/security/2002/dsa-096
Risk factor : High';

if (description) {
 script_id(14933);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "096");
 script_cve_id("CVE-2002-0001");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA096] DSA-096-2 mutt");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-096-2 mutt");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mutt', release: '2.2', reference: '1.2.5-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mutt is vulnerable in Debian 2.2.\nUpgrade to mutt_1.2.5-5\n');
}
if (w) { security_hole(port: 0, data: desc); }
