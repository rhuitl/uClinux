# This script was automatically generated from the dsa-754
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Eric Romang discovered that centericq, a text-mode multi-protocol
instant messenger client, creates some temporary files with
predictable filenames and is hence vulnerable to symlink attacks by
local attackers.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 4.20.0-1sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 4.20.0-7.
We recommend that you upgrade your centericq package.


Solution : http://www.debian.org/security/2005/dsa-754
Risk factor : High';

if (description) {
 script_id(19188);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "754");
 script_cve_id("CVE-2005-1914");
 script_bugtraq_id(14144);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA754] DSA-754-1 centericq");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-754-1 centericq");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'centericq', release: '', reference: '4.20.0-7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package centericq is vulnerable in Debian .\nUpgrade to centericq_4.20.0-7\n');
}
if (deb_check(prefix: 'centericq', release: '3.1', reference: '4.20.0-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package centericq is vulnerable in Debian 3.1.\nUpgrade to centericq_4.20.0-1sarge1\n');
}
if (deb_check(prefix: 'centericq-common', release: '3.1', reference: '4.20.0-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package centericq-common is vulnerable in Debian 3.1.\nUpgrade to centericq-common_4.20.0-1sarge1\n');
}
if (deb_check(prefix: 'centericq-fribidi', release: '3.1', reference: '4.20.0-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package centericq-fribidi is vulnerable in Debian 3.1.\nUpgrade to centericq-fribidi_4.20.0-1sarge1\n');
}
if (deb_check(prefix: 'centericq-utf8', release: '3.1', reference: '4.20.0-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package centericq-utf8 is vulnerable in Debian 3.1.\nUpgrade to centericq-utf8_4.20.0-1sarge1\n');
}
if (deb_check(prefix: 'centericq', release: '3.1', reference: '4.20.0-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package centericq is vulnerable in Debian sarge.\nUpgrade to centericq_4.20.0-1sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
