# This script was automatically generated from the dsa-923
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A buffer overflow has been discovered in dropbear, a lightweight SSH2
server and client, that may allow authenticated users to execute
arbitrary code as the server user (usually root).
The old stable distribution (woody) does not contain dropbear packages.
For the stable distribution (sarge) this problem has been fixed in
version 0.45-2sarge0.
For the unstable distribution (sid) this problem has been fixed in
version 0.47-1.
We recommend that you upgrade your dropbear package.


Solution : http://www.debian.org/security/2005/dsa-923
Risk factor : High';

if (description) {
 script_id(22789);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "923");
 script_cve_id("CVE-2005-4178");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA923] DSA-923-1 dropbear");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-923-1 dropbear");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'dropbear', release: '', reference: '0.47-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dropbear is vulnerable in Debian .\nUpgrade to dropbear_0.47-1\n');
}
if (deb_check(prefix: 'dropbear', release: '3.1', reference: '0.45-2sarge0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dropbear is vulnerable in Debian 3.1.\nUpgrade to dropbear_0.45-2sarge0\n');
}
if (deb_check(prefix: 'dropbear', release: '3.1', reference: '0.45-2sarge0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dropbear is vulnerable in Debian sarge.\nUpgrade to dropbear_0.45-2sarge0\n');
}
if (w) { security_hole(port: 0, data: desc); }
