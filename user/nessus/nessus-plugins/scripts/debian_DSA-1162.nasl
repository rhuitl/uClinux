# This script was automatically generated from the dsa-1162
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Luigi Auriemma discovered several buffer overflows in libmusicbrainz,
a CD index library, that allow remote attackers to cause a denial of
service or execute arbitrary code.
For the stable distribution (sarge) these problems have been fixed in
version 2.0.2-10sarge1 and 2.1.1-3sarge1.
For the unstable distribution (sid) these problems have been fixed in
version 2.1.4-1.
We recommend that you upgrade your libmusicbrainz packages.


Solution : http://www.debian.org/security/2006/dsa-1162
Risk factor : High';

if (description) {
 script_id(22704);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1162");
 script_cve_id("CVE-2006-4197");
 script_bugtraq_id(19508);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1162] DSA-1162-1 libmusicbrainz-2.0");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1162-1 libmusicbrainz-2.0");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libmusicbrainz-2.0,', release: '', reference: '2.1.4-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmusicbrainz-2.0, is vulnerable in Debian .\nUpgrade to libmusicbrainz-2.0,_2.1.4-1\n');
}
if (deb_check(prefix: 'libmusicbrainz2', release: '3.1', reference: '2.0.2-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmusicbrainz2 is vulnerable in Debian 3.1.\nUpgrade to libmusicbrainz2_2.0.2-10sarge1\n');
}
if (deb_check(prefix: 'libmusicbrainz2-dev', release: '3.1', reference: '2.0.2-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmusicbrainz2-dev is vulnerable in Debian 3.1.\nUpgrade to libmusicbrainz2-dev_2.0.2-10sarge1\n');
}
if (deb_check(prefix: 'libmusicbrainz4', release: '3.1', reference: '2.1.1-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmusicbrainz4 is vulnerable in Debian 3.1.\nUpgrade to libmusicbrainz4_2.1.1-3sarge1\n');
}
if (deb_check(prefix: 'libmusicbrainz4-dev', release: '3.1', reference: '2.1.1-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmusicbrainz4-dev is vulnerable in Debian 3.1.\nUpgrade to libmusicbrainz4-dev_2.1.1-3sarge1\n');
}
if (deb_check(prefix: 'python-musicbrainz', release: '3.1', reference: '2.0.2-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python-musicbrainz is vulnerable in Debian 3.1.\nUpgrade to python-musicbrainz_2.0.2-10sarge1\n');
}
if (deb_check(prefix: 'python2.1-musicbrainz', release: '3.1', reference: '2.0.2-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.1-musicbrainz is vulnerable in Debian 3.1.\nUpgrade to python2.1-musicbrainz_2.0.2-10sarge1\n');
}
if (deb_check(prefix: 'python2.2-musicbrainz', release: '3.1', reference: '2.0.2-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.2-musicbrainz is vulnerable in Debian 3.1.\nUpgrade to python2.2-musicbrainz_2.0.2-10sarge1\n');
}
if (deb_check(prefix: 'python2.3-musicbrainz', release: '3.1', reference: '2.0.2-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.3-musicbrainz is vulnerable in Debian 3.1.\nUpgrade to python2.3-musicbrainz_2.0.2-10sarge1\n');
}
if (deb_check(prefix: 'libmusicbrainz-2.0,', release: '3.1', reference: '2.0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmusicbrainz-2.0, is vulnerable in Debian sarge.\nUpgrade to libmusicbrainz-2.0,_2.0\n');
}
if (w) { security_hole(port: 0, data: desc); }
