# This script was automatically generated from the dsa-825
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
David Watson discovered a bug in mount as provided by util-linux and
other packages such as loop-aes-utils that allows local users to
bypass filesystem access restrictions by re-mounting it read-only.
The old stable distribution (woody) does not contain loop-aes-utils
packages.
For the stable distribution (sarge) this problem has been fixed in
version 2.12p-4sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 2.12p-9.
We recommend that you upgrade your loop-aes-utils package.


Solution : http://www.debian.org/security/2005/dsa-825
Risk factor : High';

if (description) {
 script_id(19794);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "825");
 script_cve_id("CVE-2005-2876");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA825] DSA-825-1 loop-aes-utils");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-825-1 loop-aes-utils");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'loop-aes-utils', release: '', reference: '2.12p-9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package loop-aes-utils is vulnerable in Debian .\nUpgrade to loop-aes-utils_2.12p-9\n');
}
if (deb_check(prefix: 'loop-aes-utils', release: '3.1', reference: '2.12p-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package loop-aes-utils is vulnerable in Debian 3.1.\nUpgrade to loop-aes-utils_2.12p-4sarge1\n');
}
if (deb_check(prefix: 'loop-aes-utils', release: '3.1', reference: '2.12p-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package loop-aes-utils is vulnerable in Debian sarge.\nUpgrade to loop-aes-utils_2.12p-4sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
