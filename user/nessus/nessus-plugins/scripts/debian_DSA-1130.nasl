# This script was automatically generated from the dsa-1130
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A cross-site scripting vulnerability has been discovered in sitebar,
a web based bookmark manager written in PHP, which allows remote
attackers to inject arbitrary web script or HTML.
For the stable distribution (sarge) this problem has been fixed in
version 3.2.6-7.1.
For the unstable distribution (sid) this problem has been fixed in
version 3.3.8-1.1.
We recommend that you upgrade your sitebar package.


Solution : http://www.debian.org/security/2006/dsa-1130
Risk factor : High';

if (description) {
 script_id(22672);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1130");
 script_cve_id("CVE-2006-3320");
 script_bugtraq_id(18680);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1130] DSA-1130-1 sitebar");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1130-1 sitebar");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'sitebar', release: '', reference: '3.3.8-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sitebar is vulnerable in Debian .\nUpgrade to sitebar_3.3.8-1.1\n');
}
if (deb_check(prefix: 'sitebar', release: '3.1', reference: '3.2.6-7.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sitebar is vulnerable in Debian 3.1.\nUpgrade to sitebar_3.2.6-7.1\n');
}
if (deb_check(prefix: 'sitebar', release: '3.1', reference: '3.2.6-7.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sitebar is vulnerable in Debian sarge.\nUpgrade to sitebar_3.2.6-7.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
