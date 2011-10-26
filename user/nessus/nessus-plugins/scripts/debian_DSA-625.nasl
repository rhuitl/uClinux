# This script was automatically generated from the dsa-625
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Danny Lungstrom discovered two buffer overflows in pcal, a program to
generate Postscript calendars, that could lead to the execution of
arbitrary code when compiling a calendar.
For the stable distribution (woody) these problems have been fixed in
version 4.7-8woody1.
For the unstable distribution (sid) these problems have been fixed in
version 4.8.0-1.
We recommend that you upgrade your pcal package.


Solution : http://www.debian.org/security/2005/dsa-625
Risk factor : High';

if (description) {
 script_id(16103);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "625");
 script_cve_id("CVE-2004-1289");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA625] DSA-625-1 pcal");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-625-1 pcal");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'pcal', release: '3.0', reference: '4.7-8woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pcal is vulnerable in Debian 3.0.\nUpgrade to pcal_4.7-8woody1\n');
}
if (deb_check(prefix: 'pcal', release: '3.1', reference: '4.8.0-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pcal is vulnerable in Debian 3.1.\nUpgrade to pcal_4.8.0-1\n');
}
if (deb_check(prefix: 'pcal', release: '3.0', reference: '4.7-8woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pcal is vulnerable in Debian woody.\nUpgrade to pcal_4.7-8woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
