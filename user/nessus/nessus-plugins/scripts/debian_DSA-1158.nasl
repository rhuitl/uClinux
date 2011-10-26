# This script was automatically generated from the dsa-1158
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Ulf Härnhammer from the Debian Security Audit Project discovered that
streamripper, a utility to record online radio-streams, performs
insufficient sanitising of data received from the streaming server,
which might lead to buffer overflows and the execution of arbitrary
code.
For the stable distribution (sarge) this problem has been fixed in
version 1.61.7-1sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 1.61.25-2.
We recommend that you upgrade your streamripper package.


Solution : http://www.debian.org/security/2006/dsa-1158
Risk factor : High';

if (description) {
 script_id(22700);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1158");
 script_cve_id("CVE-2006-3124");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1158] DSA-1158-1 streamripper");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1158-1 streamripper");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'streamripper', release: '', reference: '1.61.25-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package streamripper is vulnerable in Debian .\nUpgrade to streamripper_1.61.25-2\n');
}
if (deb_check(prefix: 'streamripper', release: '3.1', reference: '1.61.7-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package streamripper is vulnerable in Debian 3.1.\nUpgrade to streamripper_1.61.7-1sarge1\n');
}
if (deb_check(prefix: 'streamripper', release: '3.1', reference: '1.61.7-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package streamripper is vulnerable in Debian sarge.\nUpgrade to streamripper_1.61.7-1sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
