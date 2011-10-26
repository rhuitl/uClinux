# This script was automatically generated from the dsa-876
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Ulf Härnhammar discovered a buffer overflow in lynx, a text-mode
browser for the WWW that can be remotely exploited.  During the
handling of Asian characters when connecting to an NNTP server lynx
can be tricked to write past the boundary of a buffer which can lead
to the execution of arbitrary code.
For the old stable distribution (woody) this problem has been fixed in
version 2.8.4.1b-3.2.
For the stable distribution (sarge) this problem has been fixed in
version 2.8.5-2sarge1 of lynx.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you upgrade your lynx-ssl package.


Solution : http://www.debian.org/security/2005/dsa-876
Risk factor : High';

if (description) {
 script_id(22742);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "876");
 script_cve_id("CVE-2005-3120");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA876] DSA-876-1 lynx-ssl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-876-1 lynx-ssl");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'lynx-ssl', release: '3.0', reference: '2.8.4.1b-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lynx-ssl is vulnerable in Debian 3.0.\nUpgrade to lynx-ssl_2.8.4.1b-3.2\n');
}
if (deb_check(prefix: 'lynx-ssl', release: '3.1', reference: '2.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lynx-ssl is vulnerable in Debian sarge.\nUpgrade to lynx-ssl_2.8\n');
}
if (deb_check(prefix: 'lynx-ssl', release: '3.0', reference: '2.8.4.1b-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lynx-ssl is vulnerable in Debian woody.\nUpgrade to lynx-ssl_2.8.4.1b-3.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
