# This script was automatically generated from the dsa-460
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Alan Cox discovered that the isag utility (which graphically displays
data collected by the sysstat tools), creates a temporary file without
taking proper precautions.  This vulnerability could allow a local
attacker to overwrite files with the privileges of the user invoking
isag.
For the current stable distribution (woody) this problem has been
fixed in version 5.0.1-1.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you update your sysstat package.


Solution : http://www.debian.org/security/2004/dsa-460
Risk factor : High';

if (description) {
 script_id(15297);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "460");
 script_cve_id("CVE-2004-0108");
 script_bugtraq_id(9844);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA460] DSA-460-1 sysstat");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-460-1 sysstat");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'isag', release: '3.0', reference: '4.0.4-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package isag is vulnerable in Debian 3.0.\nUpgrade to isag_4.0.4-1woody1\n');
}
if (deb_check(prefix: 'sysstat', release: '3.0', reference: '4.0.4-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sysstat is vulnerable in Debian 3.0.\nUpgrade to sysstat_4.0.4-1woody1\n');
}
if (deb_check(prefix: 'sysstat', release: '3.0', reference: '5.0.1-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sysstat is vulnerable in Debian woody.\nUpgrade to sysstat_5.0.1-1\n');
}
if (w) { security_hole(port: 0, data: desc); }
