# This script was automatically generated from the dsa-709
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Sylvain Defresne discovered a buffer overflow in libexif, a library
that parses EXIF files (such as JPEG files with extra tags).  This bug
could be exploited to crash the application and maybe to execute
arbitrary code as well.
For the stable distribution (woody) this problem has been fixed in
version 0.5.0-1woody1.
For the unstable distribution (sid) this problem has been fixed in
version 0.6.9-5.
We recommend that you upgrade your libexif package.


Solution : http://www.debian.org/security/2005/dsa-709
Risk factor : High';

if (description) {
 script_id(18056);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "709");
 script_cve_id("CVE-2005-0664");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA709] DSA-709-1 libexif");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-709-1 libexif");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libexif-dev', release: '3.0', reference: '0.5.0-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libexif-dev is vulnerable in Debian 3.0.\nUpgrade to libexif-dev_0.5.0-1woody1\n');
}
if (deb_check(prefix: 'libexif5', release: '3.0', reference: '0.5.0-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libexif5 is vulnerable in Debian 3.0.\nUpgrade to libexif5_0.5.0-1woody1\n');
}
if (deb_check(prefix: 'libexif', release: '3.1', reference: '0.6.9-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libexif is vulnerable in Debian 3.1.\nUpgrade to libexif_0.6.9-5\n');
}
if (deb_check(prefix: 'libexif', release: '3.0', reference: '0.5.0-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libexif is vulnerable in Debian woody.\nUpgrade to libexif_0.5.0-1woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
