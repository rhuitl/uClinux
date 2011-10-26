# This script was automatically generated from the dsa-603
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Trustix developers discovered insecure temporary file creation in a
supplemental script (der_chop) of the openssl package which may allow
local users to overwrite files via a symlink attack.
For the stable distribution (woody) this problem has been fixed in
version 0.9.6c-2.woody.7.
For the unstable distribution (sid) this problem has been fixed in
version 0.9.7e-1.
We recommend that you upgrade your openssl package.


Solution : http://www.debian.org/security/2004/dsa-603
Risk factor : High';

if (description) {
 script_id(15893);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "603");
 script_cve_id("CVE-2004-0975");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA603] DSA-603-1 openssl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-603-1 openssl");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libssl-dev', release: '3.0', reference: '0.9.6c-2.woody.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libssl-dev is vulnerable in Debian 3.0.\nUpgrade to libssl-dev_0.9.6c-2.woody.7\n');
}
if (deb_check(prefix: 'libssl0.9.6', release: '3.0', reference: '0.9.6c-2.woody.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libssl0.9.6 is vulnerable in Debian 3.0.\nUpgrade to libssl0.9.6_0.9.6c-2.woody.7\n');
}
if (deb_check(prefix: 'openssl', release: '3.0', reference: '0.9.6c-2.woody.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openssl is vulnerable in Debian 3.0.\nUpgrade to openssl_0.9.6c-2.woody.7\n');
}
if (deb_check(prefix: 'ssleay', release: '3.0', reference: '0.9.6c-2.woody.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ssleay is vulnerable in Debian 3.0.\nUpgrade to ssleay_0.9.6c-2.woody.7\n');
}
if (deb_check(prefix: 'openssl', release: '3.1', reference: '0.9.7e-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openssl is vulnerable in Debian 3.1.\nUpgrade to openssl_0.9.7e-1\n');
}
if (deb_check(prefix: 'openssl', release: '3.0', reference: '0.9.6c-2.woody.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openssl is vulnerable in Debian woody.\nUpgrade to openssl_0.9.6c-2.woody.7\n');
}
if (w) { security_hole(port: 0, data: desc); }
