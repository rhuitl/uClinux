# This script was automatically generated from the dsa-550
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
iDEFENSE discovered a buffer overflow in the wv library, used to
convert and preview Microsoft Word documents.  An attacker could
create a specially crafted document that could lead wvHtml to execute
arbitrary code on the victims machine.
For the stable distribution (woody) this problem has been fixed in
version 0.7.1+rvt-2woody3.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you upgrade your wv package.


Solution : http://www.debian.org/security/2004/dsa-550
Risk factor : High';

if (description) {
 script_id(15387);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "550");
 script_cve_id("CVE-2004-0645");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA550] DSA-550-1 wv");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-550-1 wv");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'wv', release: '3.0', reference: '0.7.1+rvt-2woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package wv is vulnerable in Debian 3.0.\nUpgrade to wv_0.7.1+rvt-2woody3\n');
}
if (deb_check(prefix: 'wv', release: '3.0', reference: '0.7.1+rvt-2woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package wv is vulnerable in Debian woody.\nUpgrade to wv_0.7.1+rvt-2woody3\n');
}
if (w) { security_hole(port: 0, data: desc); }
