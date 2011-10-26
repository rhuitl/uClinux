# This script was automatically generated from the dsa-949
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Steve Kemp from the Debian Security Audit project discovered a
security related problem in crawl, another console based dungeon
exploration game in the vein of nethack and rogue.  The program
executes commands insecurely when saving or loading games which can
allow local attackers to gain group games privileges.
For the old stable distribution (woody) this problem has been fixed in
version 4.0.0beta23-2woody2.
For the stable distribution (sarge) this problem has been fixed in
version 4.0.0beta26-4sarge0.
For the unstable distribution (sid) this problem has been fixed in
version 4.0.0beta26-7.
We recommend that you upgrade your crawl package.


Solution : http://www.debian.org/security/2006/dsa-949
Risk factor : High';

if (description) {
 script_id(22815);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "949");
 script_cve_id("CVE-2006-0045");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA949] DSA-949-1 crawl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-949-1 crawl");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'crawl', release: '', reference: '4.0.0beta26-7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package crawl is vulnerable in Debian .\nUpgrade to crawl_4.0.0beta26-7\n');
}
if (deb_check(prefix: 'crawl', release: '3.0', reference: '4.0.0beta23-2woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package crawl is vulnerable in Debian 3.0.\nUpgrade to crawl_4.0.0beta23-2woody2\n');
}
if (deb_check(prefix: 'crawl', release: '3.1', reference: '4.0.0beta26-4sarge0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package crawl is vulnerable in Debian 3.1.\nUpgrade to crawl_4.0.0beta26-4sarge0\n');
}
if (deb_check(prefix: 'crawl', release: '3.1', reference: '4.0.0beta26-4sarge0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package crawl is vulnerable in Debian sarge.\nUpgrade to crawl_4.0.0beta26-4sarge0\n');
}
if (deb_check(prefix: 'crawl', release: '3.0', reference: '4.0.0beta23-2woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package crawl is vulnerable in Debian woody.\nUpgrade to crawl_4.0.0beta23-2woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
