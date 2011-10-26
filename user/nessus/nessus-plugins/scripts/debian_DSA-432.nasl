# This script was automatically generated from the dsa-432
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Steve Kemp from the Debian Security Audit Project discovered a problem in
crawl, another console based dungeon exploration game, in the vein of
nethack and rogue.  The program uses several environment variables as
inputs but doesn\'t apply a size check before copying one of them into
a fixed size buffer.
For the stable distribution (woody) this problem has been fixed in
version 4.0.0beta23-2woody1.
For the unstable distribution (sid) this problem has been fixed in
version 4.0.0beta26-4.
We recommend that you upgrade your crawl package.


Solution : http://www.debian.org/security/2004/dsa-432
Risk factor : High';

if (description) {
 script_id(15269);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "432");
 script_cve_id("CVE-2004-0103");
 script_bugtraq_id(9566);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA432] DSA-432-1 crawl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-432-1 crawl");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'crawl', release: '3.0', reference: '4.0.0beta23-2woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package crawl is vulnerable in Debian 3.0.\nUpgrade to crawl_4.0.0beta23-2woody1\n');
}
if (deb_check(prefix: 'crawl', release: '3.1', reference: '4.0.0beta26-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package crawl is vulnerable in Debian 3.1.\nUpgrade to crawl_4.0.0beta26-4\n');
}
if (deb_check(prefix: 'crawl', release: '3.0', reference: '4.0.0beta23-2woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package crawl is vulnerable in Debian woody.\nUpgrade to crawl_4.0.0beta23-2woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
