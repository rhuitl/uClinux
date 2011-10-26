# This script was automatically generated from the dsa-1099
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Michael Marek discovered that the Horde web application framework performs
insufficient input sanitising, which might lead to the injection of web
script code through cross-site scripting.
The old stable distribution (woody) does not contain horde2 packages.
For the stable distribution (sarge) this problem has been fixed in
version 2.2.8-1sarge3.
The unstable distribution (sid) does no longer contain horde2 packages.
We recommend that you upgrade your horde2 package.


Solution : http://www.debian.org/security/2006/dsa-1099
Risk factor : High';

if (description) {
 script_id(22641);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1099");
 script_cve_id("CVE-2006-2195");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1099] DSA-1099-1 horde2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1099-1 horde2");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'horde2', release: '3.1', reference: '2.2.8-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package horde2 is vulnerable in Debian 3.1.\nUpgrade to horde2_2.2.8-1sarge3\n');
}
if (deb_check(prefix: 'horde2', release: '3.1', reference: '2.2.8-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package horde2 is vulnerable in Debian sarge.\nUpgrade to horde2_2.2.8-1sarge3\n');
}
if (w) { security_hole(port: 0, data: desc); }
