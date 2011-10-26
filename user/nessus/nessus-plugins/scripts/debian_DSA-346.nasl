# This script was automatically generated from the dsa-346
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Albert Puigsech Galicia ripe@7a69ezine.org reported that phpsysinfo,
a web-based program to display status information about the system,
contains two vulnerabilities which could allow local files to be read,
or arbitrary PHP code to be executed, under the privileges of the web
server process (usually www-data).  These vulnerabilities require
access to a writable directory on the system in order to be exploited.
For the stable distribution (woody) this problem has been fixed in
version 2.0-3woody1.
For the unstable distribution (sid) this problem will be fixed soon.
See Debian bug #200543.
We recommend that you update your phpsysinfo package.


Solution : http://www.debian.org/security/2003/dsa-346
Risk factor : High';

if (description) {
 script_id(15183);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "346");
 script_cve_id("CVE-2003-0536");
 script_bugtraq_id(7275, 7286);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA346] DSA-346-1 phpsysinfo");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-346-1 phpsysinfo");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'phpsysinfo', release: '3.0', reference: '2.0-3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpsysinfo is vulnerable in Debian 3.0.\nUpgrade to phpsysinfo_2.0-3woody1\n');
}
if (deb_check(prefix: 'phpsysinfo', release: '3.0', reference: '2.0-3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpsysinfo is vulnerable in Debian woody.\nUpgrade to phpsysinfo_2.0-3woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
