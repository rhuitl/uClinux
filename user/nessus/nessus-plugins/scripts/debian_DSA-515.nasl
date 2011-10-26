# This script was automatically generated from the dsa-515
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Two vulnerabilities were discovered in lha:
For the current stable distribution (woody), these problems have been
fixed in version 1.14i-2woody1.
For the unstable distribution (sid), these problems have been fixed in
version 1.14i-8.
We recommend that you update your lha package.


Solution : http://www.debian.org/security/2004/dsa-515
Risk factor : High';

if (description) {
 script_id(15352);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "515");
 script_cve_id("CVE-2004-0234", "CVE-2004-0235");
 script_bugtraq_id(10243);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA515] DSA-515-1 lha");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-515-1 lha");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'lha', release: '3.0', reference: '1.14i-2woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lha is vulnerable in Debian 3.0.\nUpgrade to lha_1.14i-2woody1\n');
}
if (deb_check(prefix: 'lha', release: '3.1', reference: '1.14i-8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lha is vulnerable in Debian 3.1.\nUpgrade to lha_1.14i-8\n');
}
if (deb_check(prefix: 'lha', release: '3.0', reference: '1.14i-2woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lha is vulnerable in Debian woody.\nUpgrade to lha_1.14i-2woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
