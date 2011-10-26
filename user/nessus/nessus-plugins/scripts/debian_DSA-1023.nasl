# This script was automatically generated from the dsa-1023
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Marcus Meissner discovered that kaffeine, a versatile media player for
KDE 3, contains an unchecked buffer that can be overwritten remotely
when fetching remote RAM playlists which can cause the execution of
arbitrary code.
The old stable distribution (woody) does not contain kaffeine packages.
For the stable distribution (sarge) this problem has been fixed in
version 0.6-1sarge1.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you upgrade your kaffeine package.


Solution : http://www.debian.org/security/2006/dsa-1023
Risk factor : High';

if (description) {
 script_id(22565);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1023");
 script_cve_id("CVE-2006-0051");
 script_bugtraq_id(17372);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1023] DSA-1023-1 kaffeine");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1023-1 kaffeine");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'kaffeine', release: '3.1', reference: '0.6-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kaffeine is vulnerable in Debian 3.1.\nUpgrade to kaffeine_0.6-1sarge1\n');
}
if (deb_check(prefix: 'kaffeine', release: '3.1', reference: '0.6-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kaffeine is vulnerable in Debian sarge.\nUpgrade to kaffeine_0.6-1sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
