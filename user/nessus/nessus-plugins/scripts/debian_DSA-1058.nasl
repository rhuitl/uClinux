# This script was automatically generated from the dsa-1058
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Hendrik Weimer discovered that specially crafted web requests can
cause awstats, a powerful and featureful web server log analyzer, to
execute arbitrary commands.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 6.4-1sarge2.
For the unstable distribution (sid) this problem has been fixed in
version 6.5-2.
We recommend that you upgrade your awstats package.


Solution : http://www.debian.org/security/2006/dsa-1058
Risk factor : High';

if (description) {
 script_id(22600);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1058");
 script_cve_id("CVE-2006-2237");
 script_bugtraq_id(17844);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1058] DSA-1058-1 awstats");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1058-1 awstats");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'awstats', release: '', reference: '6.5-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package awstats is vulnerable in Debian .\nUpgrade to awstats_6.5-2\n');
}
if (deb_check(prefix: 'awstats', release: '3.1', reference: '6.4-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package awstats is vulnerable in Debian 3.1.\nUpgrade to awstats_6.4-1sarge2\n');
}
if (deb_check(prefix: 'awstats', release: '3.1', reference: '6.4-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package awstats is vulnerable in Debian sarge.\nUpgrade to awstats_6.4-1sarge2\n');
}
if (w) { security_hole(port: 0, data: desc); }
