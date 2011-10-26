# This script was automatically generated from the dsa-762
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Kevin Finisterre discovered two problems in the Bluetooth FTP client
from affix, user space utilities for the Affix Bluetooth protocol
stack.  The Common Vulnerabilities and Exposures project identifies
the following vulnerabilities:
    A buffer overflow allows remote attackers to execute arbitrary
    code via a long filename in an OBEX file share.
    Missing input sanitising before executing shell commands allow an
    attacker to execute arbitrary commands as root.
The old stable distribution (woody) is not affected by these problems.
For the stable distribution (sarge) these problems have been fixed in
version 2.1.1-2.
For the unstable distribution (sid) these problems have been fixed in
version 2.1.2-2.
We recommend that you upgrade your affix package.


Solution : http://www.debian.org/security/2005/dsa-762
Risk factor : High';

if (description) {
 script_id(19225);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "762");
 script_cve_id("CVE-2005-2250", "CVE-2005-2277");
 script_bugtraq_id(14230);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA762] DSA-762-1 affix");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-762-1 affix");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'affix', release: '', reference: '2.1.2-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package affix is vulnerable in Debian .\nUpgrade to affix_2.1.2-2\n');
}
if (deb_check(prefix: 'affix', release: '3.1', reference: '2.1.1-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package affix is vulnerable in Debian 3.1.\nUpgrade to affix_2.1.1-2\n');
}
if (deb_check(prefix: 'libaffix-dev', release: '3.1', reference: '2.1.1-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libaffix-dev is vulnerable in Debian 3.1.\nUpgrade to libaffix-dev_2.1.1-2\n');
}
if (deb_check(prefix: 'libaffix2', release: '3.1', reference: '2.1.1-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libaffix2 is vulnerable in Debian 3.1.\nUpgrade to libaffix2_2.1.1-2\n');
}
if (deb_check(prefix: 'affix', release: '3.1', reference: '2.1.1-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package affix is vulnerable in Debian sarge.\nUpgrade to affix_2.1.1-2\n');
}
if (w) { security_hole(port: 0, data: desc); }
