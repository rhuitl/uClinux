# This script was automatically generated from the dsa-801
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
SuSE developers discovered that ntp confuses the given group id with
the group id of the given user when called with a group id on the
commandline that is specified as a string and not as a numeric gid,
which causes ntpd to run with different privileges than intended.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 4.2.0a+stable-2sarge1.
The unstable distribution (sid) is not affected by this problem.
We recommend that you upgrade your ntp-server package.


Solution : http://www.debian.org/security/2005/dsa-801
Risk factor : High';

if (description) {
 script_id(19571);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "801");
 script_cve_id("CVE-2005-2496");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA801] DSA-801-1 ntp");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-801-1 ntp");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'ntp', release: '3.1', reference: '4.2.0a+stable-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ntp is vulnerable in Debian 3.1.\nUpgrade to ntp_4.2.0a+stable-2sarge1\n');
}
if (deb_check(prefix: 'ntp-doc', release: '3.1', reference: '4.2.0a+stable-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ntp-doc is vulnerable in Debian 3.1.\nUpgrade to ntp-doc_4.2.0a+stable-2sarge1\n');
}
if (deb_check(prefix: 'ntp-refclock', release: '3.1', reference: '4.2.0a+stable-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ntp-refclock is vulnerable in Debian 3.1.\nUpgrade to ntp-refclock_4.2.0a+stable-2sarge1\n');
}
if (deb_check(prefix: 'ntp-server', release: '3.1', reference: '4.2.0a+stable-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ntp-server is vulnerable in Debian 3.1.\nUpgrade to ntp-server_4.2.0a+stable-2sarge1\n');
}
if (deb_check(prefix: 'ntp-simple', release: '3.1', reference: '4.2.0a+stable-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ntp-simple is vulnerable in Debian 3.1.\nUpgrade to ntp-simple_4.2.0a+stable-2sarge1\n');
}
if (deb_check(prefix: 'ntpdate', release: '3.1', reference: '4.2.0a+stable-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ntpdate is vulnerable in Debian 3.1.\nUpgrade to ntpdate_4.2.0a+stable-2sarge1\n');
}
if (deb_check(prefix: 'ntp', release: '3.1', reference: '4.2.0a+stable-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ntp is vulnerable in Debian sarge.\nUpgrade to ntp_4.2.0a+stable-2sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
