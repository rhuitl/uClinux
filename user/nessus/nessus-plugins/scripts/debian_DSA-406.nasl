# This script was automatically generated from the dsa-406
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Ulf Härnhammar discovered a buffer overflow in lftp, a set of
sophisticated command-line FTP/HTTP client programs.  An attacker
could create a carefully crafted directory on a website so that the
execution of an \'ls\' or \'rels\' command would lead to the execution of
arbitrary code on the client machine.
For the stable distribution (woody) this problem has been fixed in
version 2.4.9-1woody2.
For the unstable distribution (sid) this problem has been fixed in
version 2.6.10-1.


Solution : http://www.debian.org/security/2004/dsa-406
Risk factor : High';

if (description) {
 script_id(15243);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "406");
 script_cve_id("CVE-2003-0963");
 script_bugtraq_id(9210);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA406] DSA-406-1 lftp");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-406-1 lftp");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'lftp', release: '3.0', reference: '2.4.9-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lftp is vulnerable in Debian 3.0.\nUpgrade to lftp_2.4.9-1woody2\n');
}
if (deb_check(prefix: 'lftp', release: '3.1', reference: '2.6.10-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lftp is vulnerable in Debian 3.1.\nUpgrade to lftp_2.6.10-1\n');
}
if (deb_check(prefix: 'lftp', release: '3.0', reference: '2.4.9-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lftp is vulnerable in Debian woody.\nUpgrade to lftp_2.4.9-1woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
