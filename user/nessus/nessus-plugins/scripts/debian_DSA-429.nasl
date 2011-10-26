# This script was automatically generated from the dsa-429
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Phong Nguyen identified a severe bug in the way GnuPG creates and uses
ElGamal keys for signing.  This is a significant security failure
which can lead to a compromise of almost all ElGamal keys used for
signing.
This update disables the use of this type of key.
For the current stable distribution (woody) this problem has been
fixed in version 1.0.6-4woody1.
For the unstable distribution, this problem has been fixed in version
1.2.4-1.
We recommend that you update your gnupg package.


Solution : http://www.debian.org/security/2004/dsa-429
Risk factor : High';

if (description) {
 script_id(15266);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "429");
 script_cve_id("CVE-2003-0971");
 script_bugtraq_id(9115);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA429] DSA-429-1 gnupg");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-429-1 gnupg");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gnupg', release: '3.0', reference: '1.0.6-4woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gnupg is vulnerable in Debian 3.0.\nUpgrade to gnupg_1.0.6-4woody1\n');
}
if (deb_check(prefix: 'gnupg', release: '3.0', reference: '1.0.6-4woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gnupg is vulnerable in Debian woody.\nUpgrade to gnupg_1.0.6-4woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
