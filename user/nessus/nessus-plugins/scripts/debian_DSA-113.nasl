# This script was automatically generated from the dsa-113
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several buffer overflows were fixed in the "ncurses" library in November
2000.  Unfortunately, one was missed.  This can lead to crashes when using
ncurses applications in large windows.
The Common Vulnerabilities and
Exposures project has assigned the name
CVE-2002-0062 to this issue.
This problem has been fixed for the stable release of Debian in version
5.0-6.0potato2.  The testing and unstable releases contain ncurses 5.2,
which is not affected by this problem.
There are no known exploits for this problem, but we recommend that all
users upgrade ncurses immediately.


Solution : http://www.debian.org/security/2002/dsa-113
Risk factor : High';

if (description) {
 script_id(14950);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "113");
 script_cve_id("CVE-2002-0062");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA113] DSA-113-1 ncurses");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-113-1 ncurses");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libncurses5', release: '2.2', reference: '5.0-6.0potato2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libncurses5 is vulnerable in Debian 2.2.\nUpgrade to libncurses5_5.0-6.0potato2\n');
}
if (deb_check(prefix: 'libncurses5-dbg', release: '2.2', reference: '5.0-6.0potato2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libncurses5-dbg is vulnerable in Debian 2.2.\nUpgrade to libncurses5-dbg_5.0-6.0potato2\n');
}
if (deb_check(prefix: 'libncurses5-dev', release: '2.2', reference: '5.0-6.0potato2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libncurses5-dev is vulnerable in Debian 2.2.\nUpgrade to libncurses5-dev_5.0-6.0potato2\n');
}
if (deb_check(prefix: 'ncurses-base', release: '2.2', reference: '5.0-6.0potato2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ncurses-base is vulnerable in Debian 2.2.\nUpgrade to ncurses-base_5.0-6.0potato2\n');
}
if (deb_check(prefix: 'ncurses-bin', release: '2.2', reference: '5.0-6.0potato2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ncurses-bin is vulnerable in Debian 2.2.\nUpgrade to ncurses-bin_5.0-6.0potato2\n');
}
if (deb_check(prefix: 'ncurses-term', release: '2.2', reference: '5.0-6.0potato2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ncurses-term is vulnerable in Debian 2.2.\nUpgrade to ncurses-term_5.0-6.0potato2\n');
}
if (w) { security_hole(port: 0, data: desc); }
