# This script was automatically generated from the dsa-210
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
lynx (a text-only web browser) did not properly check for illegal
characters in all places, including processing of command line options,
which could be used to insert extra HTTP headers in a request.
For Debian GNU/Linux 2.2/potato this has been fixed in version 2.8.3-1.1
of the lynx package and version 2.8.3.1-1.1 of the lynx-ssl package.
For Debian GNU/Linux 3.0/woody this has been fixed in version 2.8.4.1b-3.2
of the lynx package and version 1:2.8.4.1b-3.1 of the lynx-ssl package.


Solution : http://www.debian.org/security/2002/dsa-210
Risk factor : High';

if (description) {
 script_id(15047);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "210");
 script_cve_id("CVE-2002-1405");
 script_bugtraq_id(5499);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA210] DSA-210-1 lynx");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-210-1 lynx");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'lynx', release: '2.2', reference: '2.8.3-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lynx is vulnerable in Debian 2.2.\nUpgrade to lynx_2.8.3-1.1\n');
}
if (deb_check(prefix: 'lynx-ssl', release: '2.2', reference: '2.8.3.1-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lynx-ssl is vulnerable in Debian 2.2.\nUpgrade to lynx-ssl_2.8.3.1-1.1\n');
}
if (deb_check(prefix: 'lynx', release: '3.0', reference: '2.8.4.1b-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lynx is vulnerable in Debian 3.0.\nUpgrade to lynx_2.8.4.1b-3.2\n');
}
if (deb_check(prefix: 'lynx-ssl', release: '3.0', reference: '2.8.4.1b-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lynx-ssl is vulnerable in Debian 3.0.\nUpgrade to lynx-ssl_2.8.4.1b-3.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
