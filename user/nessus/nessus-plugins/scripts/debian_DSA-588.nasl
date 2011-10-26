# This script was automatically generated from the dsa-588
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Trustix developers discovered insecure temporary file creation in
supplemental scripts in the gzip package which may allow local users
to overwrite files via a symlink attack.
For the stable distribution (woody) these problems have been fixed in
version 1.3.2-3woody3.
The unstable distribution (sid) is not affected by these problems.
We recommend that you upgrade your gzip package.


Solution : http://www.debian.org/security/2004/dsa-588
Risk factor : High';

if (description) {
 script_id(15686);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "588");
 script_cve_id("CVE-2004-0970");
 script_bugtraq_id(11288);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA588] DSA-588-1 gzip");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-588-1 gzip");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gzip', release: '3.0', reference: '1.3.2-3woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gzip is vulnerable in Debian 3.0.\nUpgrade to gzip_1.3.2-3woody3\n');
}
if (deb_check(prefix: 'gzip', release: '3.0', reference: '1.3.2-3woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gzip is vulnerable in Debian woody.\nUpgrade to gzip_1.3.2-3woody3\n');
}
if (w) { security_hole(port: 0, data: desc); }
