# This script was automatically generated from the dsa-955
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Two denial of service bugs were found in the mailman list server. In
one, attachment filenames containing UTF8 strings were not properly
parsed, which could cause the server to crash. In another, a message
containing a bad date string could cause a server crash.
The old stable distribution (woody) is not vulnerable to this issue.
For the stable distribution (sarge) this problem has been fixed in
version 2.1.5-8sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 2.1.5-10.
We recommend that you upgrade your mailman package immediately.


Solution : http://www.debian.org/security/2006/dsa-955
Risk factor : High';

if (description) {
 script_id(22821);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "955");
 script_cve_id("CVE-2005-3573", "CVE-2005-4153");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA955] DSA-955-1 mailman");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-955-1 mailman");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mailman', release: '', reference: '2.1.5-10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mailman is vulnerable in Debian .\nUpgrade to mailman_2.1.5-10\n');
}
if (deb_check(prefix: 'mailman', release: '3.1', reference: '2.1.5-8sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mailman is vulnerable in Debian 3.1.\nUpgrade to mailman_2.1.5-8sarge1\n');
}
if (deb_check(prefix: 'mailman', release: '3.1', reference: '2.1.5-8sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mailman is vulnerable in Debian sarge.\nUpgrade to mailman_2.1.5-8sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
