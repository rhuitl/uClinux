# This script was automatically generated from the dsa-1188
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several security related problems have been discovered in mailman, the
web-based GNU mailing list manager.  The Common Vulnerabilities and
Exposures project identifies the following problems:
    Moritz Naumann discovered several cross-site scripting problems
    that could allow remote attackers to inject arbitrary web script code
    or HTML.
    Moritz Naumann discovered that a remote attacker can inject
    arbitrary strings into the logfile.
For the stable distribution (sarge) these problems have been fixed in
version 2.1.5-8sarge5.
For the unstable distribution (sid) these problems have been fixed in
version 2.1.8-3.
We recommend that you upgrade your mailman package.


Solution : http://www.debian.org/security/2006/dsa-1188
Risk factor : High';

if (description) {
 script_id(22730);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1188");
 script_cve_id("CVE-2006-3636", "CVE-2006-4624");
 script_bugtraq_id(19831);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1188] DSA-1188-1 mailman");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1188-1 mailman");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mailman', release: '', reference: '2.1.8-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mailman is vulnerable in Debian .\nUpgrade to mailman_2.1.8-3\n');
}
if (deb_check(prefix: 'mailman', release: '3.1', reference: '2.1.5-8sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mailman is vulnerable in Debian 3.1.\nUpgrade to mailman_2.1.5-8sarge5\n');
}
if (deb_check(prefix: 'mailman', release: '3.1', reference: '2.1.5-8sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mailman is vulnerable in Debian sarge.\nUpgrade to mailman_2.1.5-8sarge5\n');
}
if (w) { security_hole(port: 0, data: desc); }
