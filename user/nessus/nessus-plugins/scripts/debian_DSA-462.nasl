# This script was automatically generated from the dsa-462
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Steve Kemp from the Debian Security Audit Project discovered a problem in
xitalk, a talk intercept utility for the X Window System.  A local
user can exploit this problem and execute arbitrary commands under the
GID utmp.  This could be used by an attacker to remove traces from the
utmp file.
For the stable distribution (woody) this problem has been fixed in
version 1.1.11-9.1woody1.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you upgrade your xitalk package.


Solution : http://www.debian.org/security/2004/dsa-462
Risk factor : High';

if (description) {
 script_id(15299);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "462");
 script_cve_id("CVE-2004-0151");
 script_bugtraq_id(9851);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA462] DSA-462-1 xitalk");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-462-1 xitalk");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'xitalk', release: '3.0', reference: '1.1.11-9.1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xitalk is vulnerable in Debian 3.0.\nUpgrade to xitalk_1.1.11-9.1woody1\n');
}
if (deb_check(prefix: 'xitalk', release: '3.0', reference: '1.1.11-9.1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xitalk is vulnerable in Debian woody.\nUpgrade to xitalk_1.1.11-9.1woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
