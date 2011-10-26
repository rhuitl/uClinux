# This script was automatically generated from the dsa-615
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Javier Fernández-Sanguino Peña from the Debian Security Audit Project
noticed that the debstd script from
debmake, a deprecated helper package for Debian packaging, created
temporary directories in an insecure manner.  This can be exploited by
a malicious user to overwrite arbitrary files owned by the victim.
For the stable distribution (woody) this problem has been fixed in
version 3.6.10.woody.1.
For the unstable distribution (sid) this problem has been fixed in
version 3.7.7.
We recommend that you upgrade your debmake package.


Solution : http://www.debian.org/security/2004/dsa-615
Risk factor : High';

if (description) {
 script_id(16025);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "615");
 script_cve_id("CVE-2004-1179");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA615] DSA-615-1 debmake");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-615-1 debmake");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'debmake', release: '3.0', reference: '3.6.10.woody.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package debmake is vulnerable in Debian 3.0.\nUpgrade to debmake_3.6.10.woody.1\n');
}
if (deb_check(prefix: 'debmake', release: '3.1', reference: '3.7.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package debmake is vulnerable in Debian 3.1.\nUpgrade to debmake_3.7.7\n');
}
if (deb_check(prefix: 'debmake', release: '3.0', reference: '3.6.10.woody.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package debmake is vulnerable in Debian woody.\nUpgrade to debmake_3.6.10.woody.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
