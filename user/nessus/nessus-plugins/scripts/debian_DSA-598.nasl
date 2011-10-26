# This script was automatically generated from the dsa-598
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Max Vozeler noticed that yardradius, the YARD radius authentication
and accounting server, contained a stack overflow similar to the one
from radiusd which is referenced as CVE-2001-0534.  This could lead to
the execution of arbitrary code as root.
For the stable distribution (woody) this problem has been fixed in
version 1.0.20-2woody1.
For the unstable distribution (sid) this problem has been fixed in
version 1.0.20-15.
We recommend that you upgrade your yardradius package immediately.


Solution : http://www.debian.org/security/2004/dsa-598
Risk factor : High';

if (description) {
 script_id(15831);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "598");
 script_cve_id("CVE-2004-0987");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA598] DSA-598-1 yardradius");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-598-1 yardradius");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'yardradius', release: '3.0', reference: '1.0.20-2woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package yardradius is vulnerable in Debian 3.0.\nUpgrade to yardradius_1.0.20-2woody1\n');
}
if (deb_check(prefix: 'yardradius', release: '3.1', reference: '1.0.20-15')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package yardradius is vulnerable in Debian 3.1.\nUpgrade to yardradius_1.0.20-15\n');
}
if (deb_check(prefix: 'yardradius', release: '3.0', reference: '1.0.20-2woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package yardradius is vulnerable in Debian woody.\nUpgrade to yardradius_1.0.20-2woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
