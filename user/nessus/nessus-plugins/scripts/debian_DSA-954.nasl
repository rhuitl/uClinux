# This script was automatically generated from the dsa-954
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
H D Moore has discovered that Wine, a free implementation of the Microsoft
Windows APIs, inherits a design flaw from the Windows GDI API, which may
lead to the execution of code through GDI escape functions in WMF files.
The old stable distribution (woody) does not seem to be affected by this
problem.
For the stable distribution (sarge) this problem has been fixed in
version 0.0.20050310-1.2.
For the unstable distribution (sid) this problem has been fixed in
version 0.9.2-1.
We recommend that you upgrade your wine packages.


Solution : http://www.debian.org/security/2006/dsa-954
Risk factor : High';

if (description) {
 script_id(22820);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "954");
 script_cve_id("CVE-2006-0106");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA954] DSA-954-1 wine");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-954-1 wine");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'wine', release: '', reference: '0.9.2-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package wine is vulnerable in Debian .\nUpgrade to wine_0.9.2-1\n');
}
if (deb_check(prefix: 'libwine', release: '3.1', reference: '0.0.20050310-1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libwine is vulnerable in Debian 3.1.\nUpgrade to libwine_0.0.20050310-1.2\n');
}
if (deb_check(prefix: 'libwine-alsa', release: '3.1', reference: '0.0.20050310-1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libwine-alsa is vulnerable in Debian 3.1.\nUpgrade to libwine-alsa_0.0.20050310-1.2\n');
}
if (deb_check(prefix: 'libwine-arts', release: '3.1', reference: '0.0.20050310-1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libwine-arts is vulnerable in Debian 3.1.\nUpgrade to libwine-arts_0.0.20050310-1.2\n');
}
if (deb_check(prefix: 'libwine-capi', release: '3.1', reference: '0.0.20050310-1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libwine-capi is vulnerable in Debian 3.1.\nUpgrade to libwine-capi_0.0.20050310-1.2\n');
}
if (deb_check(prefix: 'libwine-dev', release: '3.1', reference: '0.0.20050310-1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libwine-dev is vulnerable in Debian 3.1.\nUpgrade to libwine-dev_0.0.20050310-1.2\n');
}
if (deb_check(prefix: 'libwine-jack', release: '3.1', reference: '0.0.20050310-1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libwine-jack is vulnerable in Debian 3.1.\nUpgrade to libwine-jack_0.0.20050310-1.2\n');
}
if (deb_check(prefix: 'libwine-nas', release: '3.1', reference: '0.0.20050310-1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libwine-nas is vulnerable in Debian 3.1.\nUpgrade to libwine-nas_0.0.20050310-1.2\n');
}
if (deb_check(prefix: 'libwine-print', release: '3.1', reference: '0.0.20050310-1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libwine-print is vulnerable in Debian 3.1.\nUpgrade to libwine-print_0.0.20050310-1.2\n');
}
if (deb_check(prefix: 'libwine-twain', release: '3.1', reference: '0.0.20050310-1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libwine-twain is vulnerable in Debian 3.1.\nUpgrade to libwine-twain_0.0.20050310-1.2\n');
}
if (deb_check(prefix: 'wine', release: '3.1', reference: '0.0.20050310-1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package wine is vulnerable in Debian 3.1.\nUpgrade to wine_0.0.20050310-1.2\n');
}
if (deb_check(prefix: 'wine-doc', release: '3.1', reference: '0.0.20050310-1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package wine-doc is vulnerable in Debian 3.1.\nUpgrade to wine-doc_0.0.20050310-1.2\n');
}
if (deb_check(prefix: 'wine-utils', release: '3.1', reference: '0.0.20050310-1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package wine-utils is vulnerable in Debian 3.1.\nUpgrade to wine-utils_0.0.20050310-1.2\n');
}
if (deb_check(prefix: 'wine', release: '3.1', reference: '0.0.20050310-1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package wine is vulnerable in Debian sarge.\nUpgrade to wine_0.0.20050310-1.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
