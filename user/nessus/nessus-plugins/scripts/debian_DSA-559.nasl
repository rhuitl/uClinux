# This script was automatically generated from the dsa-559
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Stefan Nordhausen has identified a local security hole in net-acct, a
user-mode IP accounting daemon.  Old and redundant code from some time
way back in the past created a temporary file in an insecure fashion.
For the stable distribution (woody) this problem has been fixed in
version 0.71-5woody1.
For the unstable distribution (sid) this problem has been fixed in
version 0.71-7.
We recommend that you upgrade your net-acct package.


Solution : http://www.debian.org/security/2004/dsa-559
Risk factor : High';

if (description) {
 script_id(15657);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "559");
 script_cve_id("CVE-2004-0851");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA559] DSA-559-1 net-acct");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-559-1 net-acct");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'net-acct', release: '3.0', reference: '0.71-5woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package net-acct is vulnerable in Debian 3.0.\nUpgrade to net-acct_0.71-5woody1\n');
}
if (deb_check(prefix: 'net-acct', release: '3.1', reference: '0.71-7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package net-acct is vulnerable in Debian 3.1.\nUpgrade to net-acct_0.71-7\n');
}
if (deb_check(prefix: 'net-acct', release: '3.0', reference: '0.71-5woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package net-acct is vulnerable in Debian woody.\nUpgrade to net-acct_0.71-5woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
