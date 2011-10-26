# This script was automatically generated from the dsa-889
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Hadmut Danish discovered a bug in enigmail, GPG support for Mozilla
MailNews and Mozilla Thunderbird, that can lead to the encryption of
mail with the wrong public key, hence, potential disclosure of
confidential data to others.
The old stable distribution (woody) does not contain enigmail packages.
For the stable distribution (sarge) this problem has been fixed in
version 0.91-4sarge2.
For the unstable distribution (sid) this problem has been fixed in
version 0.93-1.
We recommend that you upgrade your enigmail packages.


Solution : http://www.debian.org/security/2005/dsa-889
Risk factor : High';

if (description) {
 script_id(22755);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "889");
 script_cve_id("CVE-2005-3256");
 script_xref(name: "CERT", value: "805121");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA889] DSA-889-1 enigmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-889-1 enigmail");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'enigmail', release: '', reference: '0.93-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package enigmail is vulnerable in Debian .\nUpgrade to enigmail_0.93-1\n');
}
if (deb_check(prefix: 'mozilla-enigmail', release: '3.1', reference: '0.91-4sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-enigmail is vulnerable in Debian 3.1.\nUpgrade to mozilla-enigmail_0.91-4sarge2\n');
}
if (deb_check(prefix: 'mozilla-thunderbird-enigmail', release: '3.1', reference: '0.91-4sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-thunderbird-enigmail is vulnerable in Debian 3.1.\nUpgrade to mozilla-thunderbird-enigmail_0.91-4sarge2\n');
}
if (deb_check(prefix: 'enigmail', release: '3.1', reference: '0.91-4sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package enigmail is vulnerable in Debian sarge.\nUpgrade to enigmail_0.91-4sarge2\n');
}
if (w) { security_hole(port: 0, data: desc); }
