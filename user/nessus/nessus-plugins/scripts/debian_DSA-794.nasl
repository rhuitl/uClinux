# This script was automatically generated from the dsa-794
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Justin Rye noticed that polygen generates precompiled grammar objects
world-writable, which can be exploited by a local attacker to at least
fill up the filesystem.
The old stable distribution (woody) does not contain the polygen package.
For the stable distribution (sarge) this problem has been fixed in
version 1.0.6-7sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 1.0.6-9.
We recommend that you upgrade your polygen package.


Solution : http://www.debian.org/security/2005/dsa-794
Risk factor : High';

if (description) {
 script_id(19564);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "794");
 script_cve_id("CVE-2005-2656");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA794] DSA-794-1 polygen");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-794-1 polygen");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'polygen', release: '', reference: '1.0.6-9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package polygen is vulnerable in Debian .\nUpgrade to polygen_1.0.6-9\n');
}
if (deb_check(prefix: 'polygen', release: '3.1', reference: '1.0.6-7sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package polygen is vulnerable in Debian 3.1.\nUpgrade to polygen_1.0.6-7sarge1\n');
}
if (deb_check(prefix: 'polygen-data', release: '3.1', reference: '1.0.6-7sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package polygen-data is vulnerable in Debian 3.1.\nUpgrade to polygen-data_1.0.6-7sarge1\n');
}
if (deb_check(prefix: 'polygen', release: '3.1', reference: '1.0.6-7sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package polygen is vulnerable in Debian sarge.\nUpgrade to polygen_1.0.6-7sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
