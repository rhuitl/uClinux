# This script was automatically generated from the dsa-308
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Paul Szabo discovered that znew, a script included in the gzip
package, creates its temporary files without taking precautions to
avoid a symlink attack (CVE-2003-0367).
The gzexe script has a similar vulnerability which was patched in an
earlier release but inadvertently reverted.
For the stable distribution (woody) both problems have been fixed in
version 1.3.2-3woody1.
For the old stable distribution (potato) CVE-2003-0367 has been fixed
in version 1.2.4-33.2.  This version is not vulnerable to
CVE-1999-1332 due to an earlier patch.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you update your gzip package.


Solution : http://www.debian.org/security/2003/dsa-308
Risk factor : High';

if (description) {
 script_id(15145);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "308");
 script_cve_id("CVE-2003-0367", "CVE-1999-1332");
 script_bugtraq_id(7845, 7872);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA308] DSA-308-1 gzip");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-308-1 gzip");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gzip', release: '2.2', reference: '1.2.4-33.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gzip is vulnerable in Debian 2.2.\nUpgrade to gzip_1.2.4-33.2\n');
}
if (deb_check(prefix: 'gzip', release: '3.0', reference: '1.3.2-3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gzip is vulnerable in Debian 3.0.\nUpgrade to gzip_1.3.2-3woody1\n');
}
if (deb_check(prefix: 'gzip', release: '2.2', reference: '1.2.4-33.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gzip is vulnerable in Debian potato.\nUpgrade to gzip_1.2.4-33.2\n');
}
if (deb_check(prefix: 'gzip', release: '3.0', reference: '1.3.2-3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gzip is vulnerable in Debian woody.\nUpgrade to gzip_1.3.2-3woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
