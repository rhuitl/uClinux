# This script was automatically generated from the dsa-996
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Lincoln Stein discovered that the Perl Crypt::CBC module produces weak
ciphertext when used with block encryption algorithms with blocksize >
8 bytes.
The old stable distribution (woody) does not contain a Crypt::CBC module.
For the stable distribution (sarge) this problem has been fixed in
version 2.12-1sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 2.17-1.
We recommend that you upgrade your libcrypt-cbc-perl package.


Solution : http://www.debian.org/security/2006/dsa-996
Risk factor : High';

if (description) {
 script_id(22862);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "996");
 script_cve_id("CVE-2006-0898");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA996] DSA-996-1 libcrypt-cbc-perl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-996-1 libcrypt-cbc-perl");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libcrypt-cbc-perl', release: '', reference: '2.17-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libcrypt-cbc-perl is vulnerable in Debian .\nUpgrade to libcrypt-cbc-perl_2.17-1\n');
}
if (deb_check(prefix: 'libcrypt-cbc-perl', release: '3.1', reference: '2.12-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libcrypt-cbc-perl is vulnerable in Debian 3.1.\nUpgrade to libcrypt-cbc-perl_2.12-1sarge1\n');
}
if (deb_check(prefix: 'libcrypt-cbc-perl', release: '3.1', reference: '2.12-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libcrypt-cbc-perl is vulnerable in Debian sarge.\nUpgrade to libcrypt-cbc-perl_2.12-1sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
