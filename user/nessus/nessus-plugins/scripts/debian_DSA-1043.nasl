# This script was automatically generated from the dsa-1043
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Erik Sjölund discovered that abcmidi-yaps, a translator for ABC music
description files into PostScript, does not check the boundaries when
reading in ABC music files resulting in buffer overflows.
For the old stable distribution (woody) these problems have been fixed in
version 17-1woody1.
For the stable distribution (sarge) these problems have been fixed in
version 20050101-1sarge1.
For the unstable distribution (sid) these problems have been fixed in
version 20060422-1.
We recommend that you upgrade your abcmidi-yaps package.


Solution : http://www.debian.org/security/2006/dsa-1043
Risk factor : High';

if (description) {
 script_id(22585);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1043");
 script_cve_id("CVE-2006-1514");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1043] DSA-1043-1 abcmidi");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1043-1 abcmidi");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'abcmidi', release: '', reference: '20060422-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package abcmidi is vulnerable in Debian .\nUpgrade to abcmidi_20060422-1\n');
}
if (deb_check(prefix: 'abcmidi', release: '3.0', reference: '17-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package abcmidi is vulnerable in Debian 3.0.\nUpgrade to abcmidi_17-1woody1\n');
}
if (deb_check(prefix: 'abcmidi-yaps', release: '3.0', reference: '17-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package abcmidi-yaps is vulnerable in Debian 3.0.\nUpgrade to abcmidi-yaps_17-1woody1\n');
}
if (deb_check(prefix: 'abcmidi', release: '3.1', reference: '20050101-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package abcmidi is vulnerable in Debian 3.1.\nUpgrade to abcmidi_20050101-1sarge1\n');
}
if (deb_check(prefix: 'abcmidi-yaps', release: '3.1', reference: '20050101-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package abcmidi-yaps is vulnerable in Debian 3.1.\nUpgrade to abcmidi-yaps_20050101-1sarge1\n');
}
if (deb_check(prefix: 'abcmidi', release: '3.1', reference: '20050101-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package abcmidi is vulnerable in Debian sarge.\nUpgrade to abcmidi_20050101-1sarge1\n');
}
if (deb_check(prefix: 'abcmidi', release: '3.0', reference: '17-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package abcmidi is vulnerable in Debian woody.\nUpgrade to abcmidi_17-1woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
