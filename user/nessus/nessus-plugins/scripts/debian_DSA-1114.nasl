# This script was automatically generated from the dsa-1114
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Andreas Seltenreich discovered a buffer overflow in hashcash, a
postage payment scheme for email that is based on hash calculations,
which could allow attackers to execute arbitrary code via specially
crafted entries.
For the stable distribution (sarge) this problem has been fixed in
version 1.17-1sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 1.21-1.
We recommend that you upgrade your hashcash package.


Solution : http://www.debian.org/security/2006/dsa-1114
Risk factor : High';

if (description) {
 script_id(22656);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1114");
 script_cve_id("CVE-2006-3251");
 script_bugtraq_id(18659);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1114] DSA-1114-1 hashcash");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1114-1 hashcash");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'hashcash', release: '', reference: '1.21-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hashcash is vulnerable in Debian .\nUpgrade to hashcash_1.21-1\n');
}
if (deb_check(prefix: 'hashcash', release: '3.1', reference: '1.17-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hashcash is vulnerable in Debian 3.1.\nUpgrade to hashcash_1.17-1sarge1\n');
}
if (deb_check(prefix: 'hashcash', release: '3.1', reference: '1.17-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hashcash is vulnerable in Debian sarge.\nUpgrade to hashcash_1.17-1sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
