# This script was automatically generated from the dsa-415
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Two vulnerabilities were discovered in zebra, an IP routing daemon:
For the current stable distribution (woody) this problem has been
fixed in version 0.92a-5woody2.
The zebra package has been obsoleted in the unstable distribution by
GNU Quagga, where this problem was fixed in version 0.96.4x-4.
We recommend that you update your zebra package.


Solution : http://www.debian.org/security/2004/dsa-415
Risk factor : High';

if (description) {
 script_id(15252);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "415");
 script_cve_id("CVE-2003-0795", "CVE-2003-0858");
 script_bugtraq_id(9029);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA415] DSA-415-1 zebra");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-415-1 zebra");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'zebra', release: '3.0', reference: '0.92a-5woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package zebra is vulnerable in Debian 3.0.\nUpgrade to zebra_0.92a-5woody2\n');
}
if (deb_check(prefix: 'zebra-doc', release: '3.0', reference: '0.92a-5woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package zebra-doc is vulnerable in Debian 3.0.\nUpgrade to zebra-doc_0.92a-5woody2\n');
}
if (deb_check(prefix: 'zebra', release: '3.0', reference: '0.92a-5woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package zebra is vulnerable in Debian woody.\nUpgrade to zebra_0.92a-5woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
