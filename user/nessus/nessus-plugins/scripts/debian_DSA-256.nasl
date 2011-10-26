# This script was automatically generated from the dsa-256
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A problem has been discovered in adb2mhc from the mhc-utils package.  The
default temporary directory uses a predictable name.  This adds a
vulnerability that allows a local attacker to overwrite arbitrary
files the users has write permissions for.
For the stable distribution (woody) this problem has been
fixed in version 0.25+20010625-7.1.
The old stable distribution (potato) does not contain mhc
packages.
For the unstable distribution (sid) this problem has been fixed in
version 0.25+20030224-1.
We recommend that you upgrade your mhc-utils packages.


Solution : http://www.debian.org/security/2003/dsa-256
Risk factor : High';

if (description) {
 script_id(15093);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "256");
 script_cve_id("CVE-2003-0120");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA256] DSA-256-1 mhc");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-256-1 mhc");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mhc', release: '3.0', reference: '0.25+20010625-7.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mhc is vulnerable in Debian 3.0.\nUpgrade to mhc_0.25+20010625-7.1\n');
}
if (deb_check(prefix: 'mhc-utils', release: '3.0', reference: '0.25+20010625-7.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mhc-utils is vulnerable in Debian 3.0.\nUpgrade to mhc-utils_0.25+20010625-7.1\n');
}
if (deb_check(prefix: 'mhc', release: '3.1', reference: '0.25+20030224-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mhc is vulnerable in Debian 3.1.\nUpgrade to mhc_0.25+20030224-1\n');
}
if (deb_check(prefix: 'mhc', release: '3.0', reference: '0.25+20010625-7.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mhc is vulnerable in Debian woody.\nUpgrade to mhc_0.25+20010625-7.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
