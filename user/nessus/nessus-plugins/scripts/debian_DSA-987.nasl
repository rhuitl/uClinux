# This script was automatically generated from the dsa-987
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Jim Meyering discovered several buffer overflows in GNU tar, which may
lead to the execution of arbitrary code through specially crafted tar
archives.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 1.14-2.1.
For the unstable distribution (sid) this problem has been fixed in
version 1.15.1-3.
We recommend that you upgrade your tar package.


Solution : http://www.debian.org/security/2006/dsa-987
Risk factor : High';

if (description) {
 script_id(22853);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "987");
 script_cve_id("CVE-2006-0300");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA987] DSA-987-1 tar");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-987-1 tar");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'tar', release: '', reference: '1.15.1-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tar is vulnerable in Debian .\nUpgrade to tar_1.15.1-3\n');
}
if (deb_check(prefix: 'tar', release: '3.1', reference: '1.14-2.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tar is vulnerable in Debian 3.1.\nUpgrade to tar_1.14-2.1\n');
}
if (deb_check(prefix: 'tar', release: '3.1', reference: '1.14-2.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tar is vulnerable in Debian sarge.\nUpgrade to tar_1.14-2.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
