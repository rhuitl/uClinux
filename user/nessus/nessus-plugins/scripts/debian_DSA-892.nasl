# This script was automatically generated from the dsa-892
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Peter Vreugdenhil discovered that awstats, a featureful web server log
analyser, passes user-supplied data to an eval() function, allowing
remote attackers to execute arbitrary Perl commands.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 6.4-1sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 6.4-1.1.
We recommend that you upgrade your awstats package.


Solution : http://www.debian.org/security/2005/dsa-892
Risk factor : High';

if (description) {
 script_id(22758);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "892");
 script_cve_id("CVE-2005-1527");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA892] DSA-892-1 awstats");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-892-1 awstats");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'awstats', release: '', reference: '6.4-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package awstats is vulnerable in Debian .\nUpgrade to awstats_6.4-1.1\n');
}
if (deb_check(prefix: 'awstats', release: '3.1', reference: '6.4-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package awstats is vulnerable in Debian 3.1.\nUpgrade to awstats_6.4-1sarge1\n');
}
if (deb_check(prefix: 'awstats', release: '3.1', reference: '6.4-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package awstats is vulnerable in Debian sarge.\nUpgrade to awstats_6.4-1sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
