# This script was automatically generated from the dsa-997
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Stefan Cornelius of Gentoo Security discovered that bomberclone, a
free Bomberman-like game, crashes when receiving overly long error
packets, which may also allow remote attackers to execute arbitrary
code.
The old stable distribution (woody) does not contain bomberclone packages.
For the stable distribution (sarge) these problems have been fixed in
version 0.11.5-1sarge1.
For the unstable distribution (sid) these problems have been fixed in
version 0.11.6.2-1.
We recommend that you upgrade your bomberclone package.


Solution : http://www.debian.org/security/2006/dsa-997
Risk factor : High';

if (description) {
 script_id(22863);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "997");
 script_cve_id("CVE-2006-0460");
 script_bugtraq_id(16697);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA997] DSA-997-1 bomberclone");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-997-1 bomberclone");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'bomberclone', release: '', reference: '0.11.6.2-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bomberclone is vulnerable in Debian .\nUpgrade to bomberclone_0.11.6.2-1\n');
}
if (deb_check(prefix: 'bomberclone', release: '3.1', reference: '0.11.5-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bomberclone is vulnerable in Debian 3.1.\nUpgrade to bomberclone_0.11.5-1sarge1\n');
}
if (deb_check(prefix: 'bomberclone-data', release: '3.1', reference: '0.11.5-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bomberclone-data is vulnerable in Debian 3.1.\nUpgrade to bomberclone-data_0.11.5-1sarge1\n');
}
if (deb_check(prefix: 'bomberclone', release: '3.1', reference: '0.11.5-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bomberclone is vulnerable in Debian sarge.\nUpgrade to bomberclone_0.11.5-1sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
