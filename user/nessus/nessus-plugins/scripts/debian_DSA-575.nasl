# This script was automatically generated from the dsa-575
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A temporary file problem has been discovered in xlsview from the
catdoc suite, convertors from Word to TeX and plain text, which could
lead to local users being able to overwrite arbitrary files via a
symlink attack on predictable temporary file names.
For the stable distribution (woody) this problem has been fixed in
version 0.91.5-1.woody3.
For the unstable distribution (sid) this problem has been fixed in
version 0.91.5-2.
We recommend that you upgrade your catdoc package.


Solution : http://www.debian.org/security/2004/dsa-575
Risk factor : High';

if (description) {
 script_id(15673);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "575");
 script_cve_id("CVE-2003-0193");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA575] DSA-575-1 catdoc");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-575-1 catdoc");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'catdoc', release: '3.0', reference: '0.91.5-1.woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package catdoc is vulnerable in Debian 3.0.\nUpgrade to catdoc_0.91.5-1.woody3\n');
}
if (deb_check(prefix: 'catdoc', release: '3.1', reference: '0.91.5-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package catdoc is vulnerable in Debian 3.1.\nUpgrade to catdoc_0.91.5-2\n');
}
if (deb_check(prefix: 'catdoc', release: '3.0', reference: '0.91.5-1.woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package catdoc is vulnerable in Debian woody.\nUpgrade to catdoc_0.91.5-1.woody3\n');
}
if (w) { security_hole(port: 0, data: desc); }
