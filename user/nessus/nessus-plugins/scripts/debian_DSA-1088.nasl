# This script was automatically generated from the dsa-1088
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Mehdi Oudad and Kevin Fernandez discovered a buffer overflow in the
ktools library which is used in centericq, a text-mode multi-protocol
instant messenger client, which may lead local or remote attackers to
execute arbitrary code.
For the old stable distribution (woody) this problem has been fixed in
version 4.5.1-1.1woody2.
For the stable distribution (sarge) this problem has been fixed in
version 4.20.0-1sarge4.
For the unstable distribution (sid) this problem has been fixed in
version 4.21.0-6.
We recommend that you upgrade your centericq package.


Solution : http://www.debian.org/security/2006/dsa-1088
Risk factor : High';

if (description) {
 script_id(22630);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1088");
 script_cve_id("CVE-2005-3863");
 script_bugtraq_id(15600);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1088] DSA-1088-1 centericq");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1088-1 centericq");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'centericq', release: '', reference: '4.21.0-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package centericq is vulnerable in Debian .\nUpgrade to centericq_4.21.0-6\n');
}
if (deb_check(prefix: 'centericq', release: '3.0', reference: '4.5.1-1.1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package centericq is vulnerable in Debian 3.0.\nUpgrade to centericq_4.5.1-1.1woody2\n');
}
if (deb_check(prefix: 'centericq', release: '3.1', reference: '4.20.0-1sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package centericq is vulnerable in Debian 3.1.\nUpgrade to centericq_4.20.0-1sarge4\n');
}
if (deb_check(prefix: 'centericq-common', release: '3.1', reference: '4.20.0-1sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package centericq-common is vulnerable in Debian 3.1.\nUpgrade to centericq-common_4.20.0-1sarge4\n');
}
if (deb_check(prefix: 'centericq-fribidi', release: '3.1', reference: '4.20.0-1sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package centericq-fribidi is vulnerable in Debian 3.1.\nUpgrade to centericq-fribidi_4.20.0-1sarge4\n');
}
if (deb_check(prefix: 'centericq-utf8', release: '3.1', reference: '4.20.0-1sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package centericq-utf8 is vulnerable in Debian 3.1.\nUpgrade to centericq-utf8_4.20.0-1sarge4\n');
}
if (deb_check(prefix: 'centericq', release: '3.1', reference: '4.20.0-1sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package centericq is vulnerable in Debian sarge.\nUpgrade to centericq_4.20.0-1sarge4\n');
}
if (deb_check(prefix: 'centericq', release: '3.0', reference: '4.5.1-1.1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package centericq is vulnerable in Debian woody.\nUpgrade to centericq_4.5.1-1.1woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
