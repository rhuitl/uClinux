# This script was automatically generated from the dsa-834
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Tavis Ormandy discovered a buffer overflow in prozilla, a
multi-threaded download accelerator, which may be exploited to execute
arbitrary code.
For the old stable distribution (woody) this problem has been fixed in
version 1.3.6-3woody3.
The stable distribution (sarge) does not contain prozilla packages.
The unstable distribution (sid) does not contain prozilla packages.
We recommend that you upgrade your prozilla package.


Solution : http://www.debian.org/security/2005/dsa-834
Risk factor : High';

if (description) {
 script_id(19803);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "834");
 script_cve_id("CVE-2005-2961");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA834] DSA-834-1 prozilla");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-834-1 prozilla");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'prozilla', release: '3.0', reference: '1.3.6-3woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package prozilla is vulnerable in Debian 3.0.\nUpgrade to prozilla_1.3.6-3woody3\n');
}
if (deb_check(prefix: 'prozilla', release: '3.0', reference: '1.3.6-3woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package prozilla is vulnerable in Debian woody.\nUpgrade to prozilla_1.3.6-3woody3\n');
}
if (w) { security_hole(port: 0, data: desc); }
