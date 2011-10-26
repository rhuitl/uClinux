# This script was automatically generated from the dsa-772
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Eduard Bloch discovered a bug in apt-cacher, a caching system for
Debian package and source files, that could allow remote attackers to
execute arbitrary commands on the caching host as user www-data.
The old stable distribution (woody) does not contain this package.
For the stable distribution (sarge) this problem has been fixed in
version 0.9.4sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 0.9.10.
We recommend that you upgrade your apt-cacher package.


Solution : http://www.debian.org/security/2005/dsa-772
Risk factor : High';

if (description) {
 script_id(19373);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "772");
 script_cve_id("CVE-2005-1854");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA772] DSA-772-1 apt-cacher");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-772-1 apt-cacher");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'apt-cacher', release: '', reference: '0.9.10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apt-cacher is vulnerable in Debian .\nUpgrade to apt-cacher_0.9.10\n');
}
if (deb_check(prefix: 'apt-cacher', release: '3.1', reference: '0.9.4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apt-cacher is vulnerable in Debian 3.1.\nUpgrade to apt-cacher_0.9.4sarge1\n');
}
if (deb_check(prefix: 'apt-cacher', release: '3.1', reference: '0.9.4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apt-cacher is vulnerable in Debian sarge.\nUpgrade to apt-cacher_0.9.4sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
