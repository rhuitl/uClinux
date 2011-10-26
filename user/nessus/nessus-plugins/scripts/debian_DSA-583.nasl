# This script was automatically generated from the dsa-583
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Trustix developers discovered insecure temporary file creation in a
supplemental script in the lvm10 package that didn\'t check for
existing temporary directories, allowing local users to overwrite
files via a symlink attack.
For the stable distribution (woody) this problem has been fixed in
version 1.0.4-5woody2.
For the unstable distribution (sid) this problem has been fixed in
version 1.0.8-8.
We recommend that you upgrade your lvm10 package.


Solution : http://www.debian.org/security/2004/dsa-583
Risk factor : High';

if (description) {
 script_id(15681);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "583");
 script_cve_id("CVE-2004-0972");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA583] DSA-583-1 lvm10");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-583-1 lvm10");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'lvm10', release: '3.0', reference: '1.0.4-5woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lvm10 is vulnerable in Debian 3.0.\nUpgrade to lvm10_1.0.4-5woody2\n');
}
if (deb_check(prefix: 'lvm10', release: '3.1', reference: '1.0.8-8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lvm10 is vulnerable in Debian 3.1.\nUpgrade to lvm10_1.0.8-8\n');
}
if (deb_check(prefix: 'lvm10', release: '3.0', reference: '1.0.4-5woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lvm10 is vulnerable in Debian woody.\nUpgrade to lvm10_1.0.4-5woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
