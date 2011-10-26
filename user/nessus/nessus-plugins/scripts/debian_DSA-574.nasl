# This script was automatically generated from the dsa-574
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The upstream developers discovered a problem in cabextract, a tool to
extract cabinet files.  The program was able to overwrite files in
upper directories.  This could lead an attacker to overwrite arbitrary
files.
For the stable distribution (woody) this problem has been fixed in
version 0.2-2b.
For the unstable distribution (sid) this problem has been fixed in
version 1.1-1.
We recommend that you upgrade your cabextract package.


Solution : http://www.debian.org/security/2004/dsa-574
Risk factor : High';

if (description) {
 script_id(15672);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "574");
 script_cve_id("CVE-2004-0916");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA574] DSA-574-1 cabextract");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-574-1 cabextract");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'cabextract', release: '3.0', reference: '0.2-2b')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cabextract is vulnerable in Debian 3.0.\nUpgrade to cabextract_0.2-2b\n');
}
if (deb_check(prefix: 'cabextract', release: '3.1', reference: '1.1-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cabextract is vulnerable in Debian 3.1.\nUpgrade to cabextract_1.1-1\n');
}
if (deb_check(prefix: 'cabextract', release: '3.0', reference: '0.2-2b')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cabextract is vulnerable in Debian woody.\nUpgrade to cabextract_0.2-2b\n');
}
if (w) { security_hole(port: 0, data: desc); }
