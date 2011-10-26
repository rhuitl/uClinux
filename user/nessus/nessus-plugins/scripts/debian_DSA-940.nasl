# This script was automatically generated from the dsa-940
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
"infamous41md" and Chris Evans discovered several heap based buffer
overflows in xpdf, the Portable Document Format (PDF) suite, which is
also present in gpdf, the GNOME version of the Portable Document
Format viewer, and which can lead to a denial of service by crashing
the application or possibly to the execution of arbitrary code.
The old stable distribution (woody) does not contain gpdf packages.
For the stable distribution (sarge) these problems have been fixed in
version 2.8.2-1.2sarge2.
For the unstable distribution (sid) these problems have been fixed in
version 2.10.0-2.
We recommend that you upgrade your gpdf package.


Solution : http://www.debian.org/security/2006/dsa-940
Risk factor : High';

if (description) {
 script_id(22806);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "940");
 script_cve_id("CVE-2005-3191", "CVE-2005-3192", "CVE-2005-3624", "CVE-2005-3625", "CVE-2005-3626", "CVE-2005-3627", "CVE-2005-3628");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA940] DSA-940-1 gpdf");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-940-1 gpdf");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gpdf', release: '', reference: '2.10.0-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gpdf is vulnerable in Debian .\nUpgrade to gpdf_2.10.0-2\n');
}
if (deb_check(prefix: 'gpdf', release: '3.1', reference: '2.8.2-1.2sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gpdf is vulnerable in Debian 3.1.\nUpgrade to gpdf_2.8.2-1.2sarge2\n');
}
if (deb_check(prefix: 'gpdf', release: '3.1', reference: '2.8.2-1.2sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gpdf is vulnerable in Debian sarge.\nUpgrade to gpdf_2.8.2-1.2sarge2\n');
}
if (w) { security_hole(port: 0, data: desc); }
