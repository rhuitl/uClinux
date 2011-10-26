# This script was automatically generated from the dsa-716
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
It has been discovered that certain malformed SNAC packets sent by
other AIM or ICQ users can trigger an infinite loop in Gaim, a
multi-protocol instant messaging client, and hence lead to a denial of
service of the client.
Two more denial of service conditions have been discovered in newer
versions of Gaim which are fixed in the package in sid but are not
present in the package in woody.
For the stable distribution (woody) this problem has been fixed in
version 0.58-2.5.
For the unstable distribution (sid) these problems have been fixed in
version 1.1.3-1.
We recommend that you upgrade your gaim packages.


Solution : http://www.debian.org/security/2005/dsa-716
Risk factor : High';

if (description) {
 script_id(18152);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "716");
 script_cve_id("CVE-2005-0472");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA716] DSA-716-1 gaim");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-716-1 gaim");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gaim', release: '3.0', reference: '0.58-2.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gaim is vulnerable in Debian 3.0.\nUpgrade to gaim_0.58-2.5\n');
}
if (deb_check(prefix: 'gaim-common', release: '3.0', reference: '0.58-2.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gaim-common is vulnerable in Debian 3.0.\nUpgrade to gaim-common_0.58-2.5\n');
}
if (deb_check(prefix: 'gaim-gnome', release: '3.0', reference: '0.58-2.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gaim-gnome is vulnerable in Debian 3.0.\nUpgrade to gaim-gnome_0.58-2.5\n');
}
if (deb_check(prefix: 'gaim', release: '3.1', reference: '1.1.3-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gaim is vulnerable in Debian 3.1.\nUpgrade to gaim_1.1.3-1\n');
}
if (deb_check(prefix: 'gaim', release: '3.0', reference: '0.58-2.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gaim is vulnerable in Debian woody.\nUpgrade to gaim_0.58-2.5\n');
}
if (w) { security_hole(port: 0, data: desc); }
