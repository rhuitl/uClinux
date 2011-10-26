# This script was automatically generated from the dsa-492
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Herbert Xu reported that local users could cause a denial of service
against iproute, a set of tools for controlling networking in Linux
kernels.  iproute uses the netlink interface to communicate with the
kernel, but failed to verify that the messages it received came from
the kernel (rather than from other user processes).
For the current stable distribution (woody) this problem has been
fixed in version 20010824-8woody1.
For the unstable distribution (sid), this problem will be fixed soon.
We recommend that you update your iproute package.


Solution : http://www.debian.org/security/2004/dsa-492
Risk factor : High';

if (description) {
 script_id(15329);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "492");
 script_cve_id("CVE-2003-0856");
 script_bugtraq_id(9092);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA492] DSA-492-1 iproute");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-492-1 iproute");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'iproute', release: '3.0', reference: '20010824-8woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package iproute is vulnerable in Debian 3.0.\nUpgrade to iproute_20010824-8woody1\n');
}
if (deb_check(prefix: 'iproute', release: '3.0', reference: '20010824-8woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package iproute is vulnerable in Debian woody.\nUpgrade to iproute_20010824-8woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
