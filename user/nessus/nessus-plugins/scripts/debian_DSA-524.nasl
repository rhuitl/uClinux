# This script was automatically generated from the dsa-524
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
jaguar@felinemenace.org discovered a format string vulnerability in
rlpr, a utility for lpd printing without using /etc/printcap.  While
investigating this vulnerability, a buffer overflow was also
discovered in related code.  By exploiting one of these
vulnerabilities, a local or remote user could potentially cause
arbitrary code to be executed with the privileges of 1) the rlprd
process (remote), or 2) root (local).
CVE-2004-0393: format string vulnerability via syslog(3) in msg()
function in rlpr
CVE-2004-0454: buffer overflow in msg() function in rlpr
For the current stable distribution (woody), this problem has been
fixed in version 2.02-7woody1.
For the unstable distribution (sid), this problem will be fixed soon.
We recommend that you update your rlpr package.


Solution : http://www.debian.org/security/2004/dsa-524
Risk factor : High';

if (description) {
 script_id(15361);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "524");
 script_cve_id("CVE-2004-0393", "CVE-2004-0454");
 script_bugtraq_id(10578);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA524] DSA-524-1 rlpr");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-524-1 rlpr");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'rlpr', release: '3.0', reference: '2.02-7woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package rlpr is vulnerable in Debian 3.0.\nUpgrade to rlpr_2.02-7woody1\n');
}
if (deb_check(prefix: 'rlpr', release: '3.0', reference: '2.02-7woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package rlpr is vulnerable in Debian woody.\nUpgrade to rlpr_2.02-7woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
