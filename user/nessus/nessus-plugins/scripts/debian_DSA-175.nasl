# This script was automatically generated from the dsa-175
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Balazs Scheidler discovered a problem in the way syslog-ng handles macro
expansion.  When a macro is expanded a static length buffer is used
accompanied by a counter.  However, when constant characters are
appended, the counter is not updated properly, leading to incorrect
boundary checking.  An attacker may be able to use specially crafted
log messages inserted via UDP which overflows the buffer.
This problem has been fixed in version 1.5.15-1.1 for the current
stable distribution (woody), in version 1.4.0rc3-3.2 for the old
stable distribution (potato) and version 1.5.21-1 for the unstable
distribution (sid).
We recommend that you upgrade your syslog-ng package immediately.


Solution : http://www.debian.org/security/2002/dsa-175
Risk factor : High';

if (description) {
 script_id(15012);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "175");
 script_cve_id("CVE-2002-1200");
 script_bugtraq_id(5934);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA175] DSA-175-1 syslog-ng");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-175-1 syslog-ng");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'syslog-ng', release: '2.2', reference: '1.4.0rc3-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package syslog-ng is vulnerable in Debian 2.2.\nUpgrade to syslog-ng_1.4.0rc3-3.2\n');
}
if (deb_check(prefix: 'syslog-ng', release: '3.0', reference: '1.5.15-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package syslog-ng is vulnerable in Debian 3.0.\nUpgrade to syslog-ng_1.5.15-1.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
