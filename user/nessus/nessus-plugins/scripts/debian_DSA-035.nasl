# This script was automatically generated from the dsa-035
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = 'It has been reported that one can tweak man2html remotely
into consuming all available memory.  This has been fixed by Nicolás Lichtmaier
with help of Stephan Kulow.

<P>We recommend you upgrade your man2html package immediately.


Solution : http://www.debian.org/security/2001/dsa-035
Risk factor : High';

if (description) {
 script_id(14872);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "035");
 script_cve_id("CVE-2001-0457");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA035] DSA-035-1 man2html");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-035-1 man2html");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'man2html', release: '2.2', reference: '1.5-23')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package man2html is vulnerable in Debian 2.2.\nUpgrade to man2html_1.5-23\n');
}
if (w) { security_hole(port: 0, data: desc); }
