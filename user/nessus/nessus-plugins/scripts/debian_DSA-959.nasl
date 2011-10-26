# This script was automatically generated from the dsa-959
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Ulf Härnhammar from the Debian Security Audit Project discovered that unalz, a
decompressor for ALZ archives, performs insufficient bounds checking
when parsing file names.  This can lead to arbitrary code execution if
an attacker provides a crafted ALZ archive.
The old stable distribution (woody) does not contain unalz.
For the stable distribution (sarge) this problem has been fixed in
version 0.30.1
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you upgrade your unalz package.


Solution : http://www.debian.org/security/2006/dsa-959
Risk factor : High';

if (description) {
 script_id(22825);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "959");
 script_cve_id("CVE-2005-3862");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA959] DSA-959-1 unalz");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-959-1 unalz");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'unalz', release: '3.1', reference: '0.30.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package unalz is vulnerable in Debian 3.1.\nUpgrade to unalz_0.30.1\n');
}
if (deb_check(prefix: 'unalz', release: '3.1', reference: '0.30')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package unalz is vulnerable in Debian sarge.\nUpgrade to unalz_0.30\n');
}
if (w) { security_hole(port: 0, data: desc); }
