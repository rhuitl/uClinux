# This script was automatically generated from the dsa-633
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Peter Samuelson, upstream maintainer of bmv, a PostScript viewer for
SVGAlib, discovered that temporary files are created in an insecure
fashion.  A malicious local user could cause arbitrary files to be
overwritten by a symlink attack.
For the stable distribution (woody) this problem has been
fixed in version 1.2-14.2.
For the unstable distribution (sid) this problem has been fixed in
version 1.2-17.
We recommend that you upgrade your bmv packages.


Solution : http://www.debian.org/security/2005/dsa-633
Risk factor : High';

if (description) {
 script_id(16130);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "633");
 script_cve_id("CVE-2003-0014");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA633] DSA-633-1 bmv");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-633-1 bmv");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'bmv', release: '3.0', reference: '1.2-14.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bmv is vulnerable in Debian 3.0.\nUpgrade to bmv_1.2-14.2\n');
}
if (deb_check(prefix: 'bmv', release: '3.1', reference: '1.2-17')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bmv is vulnerable in Debian 3.1.\nUpgrade to bmv_1.2-17\n');
}
if (deb_check(prefix: 'bmv', release: '3.0', reference: '1.2-14.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bmv is vulnerable in Debian woody.\nUpgrade to bmv_1.2-14.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
