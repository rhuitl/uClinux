# This script was automatically generated from the dsa-985
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Evgeny Legerov discovered several out-of-bounds memory accesses in the
DER decoding component of the Tiny ASN.1 Library that allows
attackers to crash the DER decoder and possibly execute arbitrary code.
The old stable distribution (woody) is not affected by these problems.
For the stable distribution (sarge) these problems have been fixed in
version 2_0.2.10-3sarge1.
For the unstable distribution (sid) these problems will be fixed soon.
We recommend that you upgrade your libtasn1 packages.


Solution : http://www.debian.org/security/2006/dsa-985
Risk factor : High';

if (description) {
 script_id(22851);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "985");
 script_cve_id("CVE-2006-0645");
 script_bugtraq_id(16568);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA985] DSA-985-1 libtasn1-2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-985-1 libtasn1-2");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libtasn1-2', release: '3.1', reference: '0.2.10-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtasn1-2 is vulnerable in Debian 3.1.\nUpgrade to libtasn1-2_0.2.10-3sarge1\n');
}
if (deb_check(prefix: 'libtasn1-2-dev', release: '3.1', reference: '0.2.10-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtasn1-2-dev is vulnerable in Debian 3.1.\nUpgrade to libtasn1-2-dev_0.2.10-3sarge1\n');
}
if (deb_check(prefix: 'libtasn1', release: '3.1', reference: '2_0.2.10-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtasn1 is vulnerable in Debian sarge.\nUpgrade to libtasn1_2_0.2.10-3sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
