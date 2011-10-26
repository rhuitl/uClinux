# This script was automatically generated from the dsa-722
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A buffer overflow has been discovered in Smail, an electronic mail
transport system, which allows remote attackers and local users to
execute arbitrary code.
For the stable distribution (woody) this problem has been fixed in
version 3.2.0.114-4woody1.
For the unstable distribution (sid) this problem has been fixed in
version 3.2.0.115-7.
We recommend that you upgrade your smail package.


Solution : http://www.debian.org/security/2005/dsa-722
Risk factor : High';

if (description) {
 script_id(18226);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "722");
 script_cve_id("CVE-2005-0892");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA722] DSA-722-1 smail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-722-1 smail");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'smail', release: '3.0', reference: '3.2.0.114-4woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package smail is vulnerable in Debian 3.0.\nUpgrade to smail_3.2.0.114-4woody1\n');
}
if (deb_check(prefix: 'smail', release: '3.1', reference: '3.2.0.115-7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package smail is vulnerable in Debian 3.1.\nUpgrade to smail_3.2.0.115-7\n');
}
if (deb_check(prefix: 'smail', release: '3.0', reference: '3.2.0.114-4woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package smail is vulnerable in Debian woody.\nUpgrade to smail_3.2.0.114-4woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
