# This script was automatically generated from the dsa-302
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Joey Hess discovered that fuzz, a software stress-testing tool,
creates a temporary file without taking appropriate security
precautions.  This bug could allow an attacker to gain the privileges
of the user invoking fuzz, excluding root (fuzz does not allow itself
to be invoked as root).
For the stable distribution (woody) this problem has been fixed in
version 0.6-6woody1.
The old stable distribution (potato) does not contain a fuzz package.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you update your fuzz package.


Solution : http://www.debian.org/security/2003/dsa-302
Risk factor : High';

if (description) {
 script_id(15139);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "302");
 script_cve_id("CVE-2003-0261");
 script_bugtraq_id(7521);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA302] DSA-302-1 fuzz");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-302-1 fuzz");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'fuzz', release: '3.0', reference: '0.6-6woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fuzz is vulnerable in Debian 3.0.\nUpgrade to fuzz_0.6-6woody1\n');
}
if (deb_check(prefix: 'fuzz', release: '3.0', reference: '0.6-6woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fuzz is vulnerable in Debian woody.\nUpgrade to fuzz_0.6-6woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
