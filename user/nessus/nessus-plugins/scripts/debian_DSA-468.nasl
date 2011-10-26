# This script was automatically generated from the dsa-468
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Ulf Härnhammar discovered a number of vulnerabilities in emil, a
filter for converting Internet mail messages.  The vulnerabilities
fall into two categories:
   Buffer overflows in (1) the encode_mime function,
   (2) the encode_uuencode function, (3) the decode_uuencode
   function.  These bugs could allow a carefully crafted email message
   to cause the execution of arbitrary code supplied with the message
   when it is acted upon by emil.
   Format string bugs in statements which print
   various error messages.  The exploit potential of these bugs has
   not been established, and is probably configuration-dependent.
For the stable distribution (woody) these problems have been fixed in
version 2.1.0-beta9-11woody1.
For the unstable distribution (sid) these problems will be fixed soon.
We recommend that you update your emil package.


Solution : http://www.debian.org/security/2004/dsa-468
Risk factor : High';

if (description) {
 script_id(15305);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "468");
 script_cve_id("CVE-2004-0152", "CVE-2004-0153");
 script_bugtraq_id(9974);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA468] DSA-468-1 emil");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-468-1 emil");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'emil', release: '3.0', reference: '2.1.0-beta9-11woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package emil is vulnerable in Debian 3.0.\nUpgrade to emil_2.1.0-beta9-11woody1\n');
}
if (deb_check(prefix: 'emil', release: '3.0', reference: '2.1.0-beta9-11woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package emil is vulnerable in Debian woody.\nUpgrade to emil_2.1.0-beta9-11woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
