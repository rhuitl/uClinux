# This script was automatically generated from the dsa-1085
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '

Several vulnerabilities have been discovered in lynx, the popular
text-mode WWW browser.  The Common Vulnerabilities and Exposures
Project identifies the following vulnerabilities:
    Michal Zalewski discovered that lynx is not able to grok invalid
    HTML including a TEXTAREA tag with a large COLS value and a large
    tag name in an element that is not terminated, and loops forever
    trying to render the broken HTML.
    Ulf Härnhammar discovered a buffer overflow that can be remotely
    exploited. During the handling of Asian characters when connecting
    to an NNTP server lynx can be tricked to write past the boundary
    of a buffer which can lead to the execution of arbitrary code.
For the old stable distribution (woody) these problems have been fixed in
version 2.8.5-2.5woody1.
For the stable distribution (sarge) these problems have been fixed in
version 2.8.6-9sarge1.
For the unstable distribution (sid) these problems will be fixed soon.
We recommend that you upgrade your lynx-cur package.


Solution : http://www.debian.org/security/2006/dsa-1085
Risk factor : High';

if (description) {
 script_id(22627);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1085");
 script_cve_id("CVE-2005-3120", "CVE-2004-1617");
 script_bugtraq_id(11443);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1085] DSA-1085-1 lynx-cur");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1085-1 lynx-cur");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'lynx-cur', release: '3.0', reference: '2.8.5-2.5woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lynx-cur is vulnerable in Debian 3.0.\nUpgrade to lynx-cur_2.8.5-2.5woody1\n');
}
if (deb_check(prefix: 'lynx-cur-wrapper', release: '3.0', reference: '2.8.5-2.5woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lynx-cur-wrapper is vulnerable in Debian 3.0.\nUpgrade to lynx-cur-wrapper_2.8.5-2.5woody1\n');
}
if (deb_check(prefix: 'lynx-cur', release: '3.1', reference: '2.8.6-9sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lynx-cur is vulnerable in Debian 3.1.\nUpgrade to lynx-cur_2.8.6-9sarge1\n');
}
if (deb_check(prefix: 'lynx-cur-wrapper', release: '3.1', reference: '2.8.6-9sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lynx-cur-wrapper is vulnerable in Debian 3.1.\nUpgrade to lynx-cur-wrapper_2.8.6-9sarge1\n');
}
if (deb_check(prefix: 'lynx-cur', release: '3.1', reference: '2.8.6-9sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lynx-cur is vulnerable in Debian sarge.\nUpgrade to lynx-cur_2.8.6-9sarge1\n');
}
if (deb_check(prefix: 'lynx-cur', release: '3.0', reference: '2.8.5-2.5woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lynx-cur is vulnerable in Debian woody.\nUpgrade to lynx-cur_2.8.5-2.5woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
