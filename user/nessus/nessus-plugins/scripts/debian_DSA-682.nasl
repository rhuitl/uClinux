# This script was automatically generated from the dsa-682
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
In addition to CVE-2005-0116 more vulnerabilities have been found in
awstats, a powerful and featureful web server log analyzer with a CGI
frontend.  Missing input sanitising can cause arbitrary commands to be
executed.
For the stable distribution (woody) this problem has been fixed in
version 4.0-0.woody.2.
For the unstable distribution (sid) this problem has been fixed in
version 6.2-1.2.
We recommend that you upgrade your awstats package.


Solution : http://www.debian.org/security/2005/dsa-682
Risk factor : High';

if (description) {
 script_id(16464);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "682");
 script_cve_id("CVE-2005-0363");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA682] DSA-682-1 awstats");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-682-1 awstats");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'awstats', release: '3.0', reference: '4.0-0.woody.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package awstats is vulnerable in Debian 3.0.\nUpgrade to awstats_4.0-0.woody.2\n');
}
if (deb_check(prefix: 'awstats', release: '3.1', reference: '6.2-1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package awstats is vulnerable in Debian 3.1.\nUpgrade to awstats_6.2-1.2\n');
}
if (deb_check(prefix: 'awstats', release: '3.0', reference: '4.0-0.woody.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package awstats is vulnerable in Debian woody.\nUpgrade to awstats_4.0-0.woody.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
