# This script was automatically generated from the dsa-411
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A vulnerability was discovered in mpg321, a command-line mp3 player,
whereby user-supplied strings were passed to printf(3) unsafely.  This
vulnerability could be exploited by a remote attacker to overwrite
memory, and possibly execute arbitrary code.  In order for this
vulnerability to be exploited, mpg321 would need to play a malicious
mp3 file (including via HTTP streaming).
For the current stable distribution (woody) this problem has been
fixed in version 0.2.10.2.
For the unstable distribution (sid) this problem has been fixed in
version 0.2.10.3.
We recommend that you update your mpg321 package.


Solution : http://www.debian.org/security/2004/dsa-411
Risk factor : High';

if (description) {
 script_id(15248);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "411");
 script_cve_id("CVE-2003-0969");
 script_bugtraq_id(9364);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA411] DSA-411-1 mpg321");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-411-1 mpg321");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mpg321', release: '3.0', reference: '0.2.10.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mpg321 is vulnerable in Debian 3.0.\nUpgrade to mpg321_0.2.10.2\n');
}
if (deb_check(prefix: 'mpg321', release: '3.1', reference: '0.2.10.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mpg321 is vulnerable in Debian 3.1.\nUpgrade to mpg321_0.2.10.3\n');
}
if (deb_check(prefix: 'mpg321', release: '3.0', reference: '0.2.10.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mpg321 is vulnerable in Debian woody.\nUpgrade to mpg321_0.2.10.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
