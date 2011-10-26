# This script was automatically generated from the dsa-277
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The controlling and management daemon apcupsd for APC\'s Unbreakable
Power Supplies is vulnerable to several buffer overflows and format
string attacks. These bugs can be exploited remotely by an attacker to gain root
access to the machine apcupsd is running on.
For the stable distribution (woody) this problem has been fixed in
version 3.8.5-1.1.1.
For the old stable distribution (potato) this problem does not seem to
exist.
For the unstable distribution (sid) this problem has been
fixed in version 3.8.5-1.2.
We recommend that you upgrade your apcupsd packages immediately.


Solution : http://www.debian.org/security/2003/dsa-277
Risk factor : High';

if (description) {
 script_id(15114);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "277");
 script_cve_id("CVE-2003-0098", "CVE-2003-0099");
 script_bugtraq_id(7200);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA277] DSA-277-1 apcupsd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-277-1 apcupsd");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'apcupsd', release: '3.0', reference: '3.8.5-1.1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apcupsd is vulnerable in Debian 3.0.\nUpgrade to apcupsd_3.8.5-1.1.1\n');
}
if (deb_check(prefix: 'apcupsd', release: '3.1', reference: '3.8.5-1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apcupsd is vulnerable in Debian 3.1.\nUpgrade to apcupsd_3.8.5-1.2\n');
}
if (deb_check(prefix: 'apcupsd', release: '3.0', reference: '3.8.5-1.1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apcupsd is vulnerable in Debian woody.\nUpgrade to apcupsd_3.8.5-1.1.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
