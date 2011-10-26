# This script was automatically generated from the dsa-1072
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A buffer overflow has been discovered in nagios, a host, service and
network monitoring and management system, that could be exploited by
remote attackers to execute arbitrary code.
The old stable distribution (woody) does not contain nagios packages.
For the stable distribution (sarge) this problem has been fixed in
version 1.3-cvs.20050402-2.sarge.2.
For the unstable distribution (sid) this problem has been fixed in
version 1.4-1 and 2.3-1.
We recommend that you upgrade your nagios package.


Solution : http://www.debian.org/security/2006/dsa-1072
Risk factor : High';

if (description) {
 script_id(22614);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1072");
 script_cve_id("CVE-2006-2162", "CVE-2006-2489");
 script_bugtraq_id(17879);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1072] DSA-1072-1 nagios");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1072-1 nagios");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'nagios', release: '', reference: '1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nagios is vulnerable in Debian .\nUpgrade to nagios_1\n');
}
if (deb_check(prefix: 'nagios-common', release: '3.1', reference: '1.3-cvs.20050402-2.sarge.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nagios-common is vulnerable in Debian 3.1.\nUpgrade to nagios-common_1.3-cvs.20050402-2.sarge.2\n');
}
if (deb_check(prefix: 'nagios-mysql', release: '3.1', reference: '1.3-cvs.20050402-2.sarge.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nagios-mysql is vulnerable in Debian 3.1.\nUpgrade to nagios-mysql_1.3-cvs.20050402-2.sarge.2\n');
}
if (deb_check(prefix: 'nagios-pgsql', release: '3.1', reference: '1.3-cvs.20050402-2.sarge.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nagios-pgsql is vulnerable in Debian 3.1.\nUpgrade to nagios-pgsql_1.3-cvs.20050402-2.sarge.2\n');
}
if (deb_check(prefix: 'nagios-text', release: '3.1', reference: '1.3-cvs.20050402-2.sarge.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nagios-text is vulnerable in Debian 3.1.\nUpgrade to nagios-text_1.3-cvs.20050402-2.sarge.2\n');
}
if (deb_check(prefix: 'nagios', release: '3.1', reference: '1.3-cvs.20050402-2.sarge.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nagios is vulnerable in Debian sarge.\nUpgrade to nagios_1.3-cvs.20050402-2.sarge.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
