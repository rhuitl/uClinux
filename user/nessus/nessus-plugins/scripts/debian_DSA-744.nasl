# This script was automatically generated from the dsa-744
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Sven Tantau discovered a security problem in fuse, a filesystem in
userspace, that can be exploited by malicious, local users to disclose
potentially sensitive information.
The old stable distribution (woody) does not contain the fuse package.
For the stable distribution (sarge) this problem has been fixed in
version 2.2.1-4sarge2.
For the unstable distribution (sid) this problem has been fixed in
version 2.3.0-1.
We recommend that you upgrade your fuse package.


Solution : http://www.debian.org/security/2005/dsa-744
Risk factor : High';

if (description) {
 script_id(18652);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "744");
 script_cve_id("CVE-2005-1858");
 script_bugtraq_id(13857);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA744] DSA-744-1 fuse");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-744-1 fuse");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'fuse', release: '', reference: '2.3.0-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fuse is vulnerable in Debian .\nUpgrade to fuse_2.3.0-1\n');
}
if (deb_check(prefix: 'fuse-source', release: '3.1', reference: '2.2.1-4sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fuse-source is vulnerable in Debian 3.1.\nUpgrade to fuse-source_2.2.1-4sarge2\n');
}
if (deb_check(prefix: 'fuse-utils', release: '3.1', reference: '2.2.1-4sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fuse-utils is vulnerable in Debian 3.1.\nUpgrade to fuse-utils_2.2.1-4sarge2\n');
}
if (deb_check(prefix: 'libfuse-dev', release: '3.1', reference: '2.2.1-4sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libfuse-dev is vulnerable in Debian 3.1.\nUpgrade to libfuse-dev_2.2.1-4sarge2\n');
}
if (deb_check(prefix: 'libfuse2', release: '3.1', reference: '2.2.1-4sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libfuse2 is vulnerable in Debian 3.1.\nUpgrade to libfuse2_2.2.1-4sarge2\n');
}
if (deb_check(prefix: 'fuse', release: '3.1', reference: '2.2.1-4sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fuse is vulnerable in Debian sarge.\nUpgrade to fuse_2.2.1-4sarge2\n');
}
if (w) { security_hole(port: 0, data: desc); }
