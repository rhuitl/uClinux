# This script was automatically generated from the dsa-192
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The SuSE Security Team found a vulnerability in html2ps, an HTML to
PostScript converter, that opened files based on unsanitized input
insecurely.  This problem can be exploited when html2ps is installed
as filter within lprng and the attacker has previously gained access
to the lp account.
These problems have been fixed in version 1.0b3-1.1 for the current
stable distribution (woody), in version 1.0b1-8.1 for the old stable
distribution (potato) and in version 1.0b3-2 for the unstable
distribution (sid).
We recommend that you upgrade your html2ps package.


Solution : http://www.debian.org/security/2002/dsa-192
Risk factor : High';

if (description) {
 script_id(15029);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "192");
 script_cve_id("CVE-2002-1275");
 script_bugtraq_id(6079);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA192] DSA-192-1 html2ps");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-192-1 html2ps");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'html2ps', release: '2.2', reference: '1.0b1-8.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package html2ps is vulnerable in Debian 2.2.\nUpgrade to html2ps_1.0b1-8.2\n');
}
if (deb_check(prefix: 'html2ps', release: '3.0', reference: '1.0b3-1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package html2ps is vulnerable in Debian 3.0.\nUpgrade to html2ps_1.0b3-1.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
