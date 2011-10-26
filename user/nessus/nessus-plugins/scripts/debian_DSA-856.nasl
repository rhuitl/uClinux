# This script was automatically generated from the dsa-856
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Arc Riley discovered that py2play, a peer-to-peer network game engine,
is able to execute arbitrary code received from the p2p game network
it is connected to without any security checks.
The old stable distribution (woody) does not contain py2play packages.
For the stable distribution (sarge) this problem has been fixed in
version 0.1.7-1sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 0.1.8-1.
We recommend that you upgrade your py2play package.


Solution : http://www.debian.org/security/2005/dsa-856
Risk factor : High';

if (description) {
 script_id(19964);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "856");
 script_cve_id("CVE-2005-2875");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA856] DSA-856-1 py2play");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-856-1 py2play");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'py2play', release: '', reference: '0.1.8-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package py2play is vulnerable in Debian .\nUpgrade to py2play_0.1.8-1\n');
}
if (deb_check(prefix: 'python-2play', release: '3.1', reference: '0.1.7-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python-2play is vulnerable in Debian 3.1.\nUpgrade to python-2play_0.1.7-1sarge1\n');
}
if (deb_check(prefix: 'py2play', release: '3.1', reference: '0.1.7-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package py2play is vulnerable in Debian sarge.\nUpgrade to py2play_0.1.7-1sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
