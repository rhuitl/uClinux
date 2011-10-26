# This script was automatically generated from the dsa-1075
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Hendrik Weimer discovered that awstats can execute arbitrary commands
under the user id the web-server runs when users are allowed to supply
arbitrary configuration files.  Even though, this bug was referenced
in DSA 1058 accidentally, it was not fixed yet.
The new default behaviour is not to accept arbitrary configuration
directories from the user.  This can be overwritten by the
AWSTATS_ENABLE_CONFIG_DIR environment variable when users are to be
trusted.
The old stable distribution (woody) does not seem to be affected by
this problem.
For the stable distribution (sarge) this problem has been fixed in
version 6.4-1sarge3.
For the unstable distribution (sid) this problem has been fixed in
version 6.5-2.
We recommend that you upgrade your awstats package.


Solution : http://www.debian.org/security/2006/dsa-1075
Risk factor : High';

if (description) {
 script_id(22617);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1075");
 script_cve_id("CVE-2006-2644");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1075] DSA-1075-1 awstats");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1075-1 awstats");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'awstats', release: '', reference: '6.5-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package awstats is vulnerable in Debian .\nUpgrade to awstats_6.5-2\n');
}
if (deb_check(prefix: 'awstats', release: '3.1', reference: '6.4-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package awstats is vulnerable in Debian 3.1.\nUpgrade to awstats_6.4-1sarge3\n');
}
if (deb_check(prefix: 'awstats', release: '3.1', reference: '6.4-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package awstats is vulnerable in Debian sarge.\nUpgrade to awstats_6.4-1sarge3\n');
}
if (w) { security_hole(port: 0, data: desc); }
