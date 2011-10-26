# This script was automatically generated from the dsa-098
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Two different problems where found in libgtop-daemon:
Since libgtop_daemon runs as user nobody both bugs could be used
to gain access as the nobody user to a system running libgtop_daemon.
Both problems have been fixed in version 1.0.6-1.1 and we recommend
you upgrade your libgtop-daemon package immediately.


Solution : http://www.debian.org/security/2002/dsa-098
Risk factor : High';

if (description) {
 script_id(14935);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "098");
 script_cve_id("CVE-2001-0927", "CVE-2001-0928");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA098] DSA-098-1 libgtop");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-098-1 libgtop");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libgtop-daemon', release: '2.2', reference: '1.0.6-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgtop-daemon is vulnerable in Debian 2.2.\nUpgrade to libgtop-daemon_1.0.6-1.1\n');
}
if (deb_check(prefix: 'libgtop-dev', release: '2.2', reference: '1.0.6-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgtop-dev is vulnerable in Debian 2.2.\nUpgrade to libgtop-dev_1.0.6-1.1\n');
}
if (deb_check(prefix: 'libgtop1', release: '2.2', reference: '1.0.6-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgtop1 is vulnerable in Debian 2.2.\nUpgrade to libgtop1_1.0.6-1.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
