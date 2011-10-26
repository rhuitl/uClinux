# This script was automatically generated from the dsa-995
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Ulf Härnhammar discovered a buffer overflow in metamail, an
implementation of MIME (Multi-purpose Internet Mail Extensions), that
could lead to a denial of service or potentially execute arbitrary
code when processing messages.
For the old stable distribution (woody) this problem has been fixed in
version 2.7-45woody.4.
For the stable distribution (sarge) this problem has been fixed in
version 2.7-47sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 2.7-51.
We recommend that you upgrade your metamail package.


Solution : http://www.debian.org/security/2006/dsa-995
Risk factor : High';

if (description) {
 script_id(22861);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "995");
 script_cve_id("CVE-2006-0709");
 script_bugtraq_id(16611);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA995] DSA-995-1 metamail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-995-1 metamail");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'metamail', release: '', reference: '2.7-51')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package metamail is vulnerable in Debian .\nUpgrade to metamail_2.7-51\n');
}
if (deb_check(prefix: 'metamail', release: '3.0', reference: '2.7-45woody.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package metamail is vulnerable in Debian 3.0.\nUpgrade to metamail_2.7-45woody.4\n');
}
if (deb_check(prefix: 'metamail', release: '3.1', reference: '2.7-47sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package metamail is vulnerable in Debian 3.1.\nUpgrade to metamail_2.7-47sarge1\n');
}
if (deb_check(prefix: 'metamail', release: '3.1', reference: '2.7-47sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package metamail is vulnerable in Debian sarge.\nUpgrade to metamail_2.7-47sarge1\n');
}
if (deb_check(prefix: 'metamail', release: '3.0', reference: '2.7-45woody.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package metamail is vulnerable in Debian woody.\nUpgrade to metamail_2.7-45woody.4\n');
}
if (w) { security_hole(port: 0, data: desc); }
