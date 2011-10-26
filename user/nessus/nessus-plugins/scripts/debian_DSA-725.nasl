# This script was automatically generated from the dsa-725
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Jens Steube discovered that ppxp, yet another PPP program, does not
release root privileges when opening potentially user supplied log
files.  This can be tricked into opening a root shell.
For the old stable distribution (woody) this problem has been
fixed in version 0.2001080415-6woody2 (DSA 725-1).
For the stable distribution (sarge) this problem has been fixed in
version 0.2001080415-10sarge2.
For the unstable distribution (sid) this problem has been fixed in
version 0.2001080415-11.
We recommend that you upgrade your ppxp package.


Solution : http://www.debian.org/security/2005/dsa-725
Risk factor : High';

if (description) {
 script_id(18304);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "725");
 script_cve_id("CVE-2005-0392");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA725] DSA-725-2 ppxp");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-725-2 ppxp");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'ppxp', release: '', reference: '0.2001080415-11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ppxp is vulnerable in Debian .\nUpgrade to ppxp_0.2001080415-11\n');
}
if (deb_check(prefix: 'ppxp', release: '3.0', reference: '0.2001080415-6woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ppxp is vulnerable in Debian 3.0.\nUpgrade to ppxp_0.2001080415-6woody2\n');
}
if (deb_check(prefix: 'ppxp-dev', release: '3.0', reference: '0.2001080415-6woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ppxp-dev is vulnerable in Debian 3.0.\nUpgrade to ppxp-dev_0.2001080415-6woody2\n');
}
if (deb_check(prefix: 'ppxp-tcltk', release: '3.0', reference: '0.2001080415-6woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ppxp-tcltk is vulnerable in Debian 3.0.\nUpgrade to ppxp-tcltk_0.2001080415-6woody2\n');
}
if (deb_check(prefix: 'ppxp-x11', release: '3.0', reference: '0.2001080415-6woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ppxp-x11 is vulnerable in Debian 3.0.\nUpgrade to ppxp-x11_0.2001080415-6woody2\n');
}
if (deb_check(prefix: 'ppxp', release: '3.1', reference: '0.2001080415-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ppxp is vulnerable in Debian 3.1.\nUpgrade to ppxp_0.2001080415-10sarge2\n');
}
if (deb_check(prefix: 'ppxp-dev', release: '3.1', reference: '0.2001080415-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ppxp-dev is vulnerable in Debian 3.1.\nUpgrade to ppxp-dev_0.2001080415-10sarge2\n');
}
if (deb_check(prefix: 'ppxp-tcltk', release: '3.1', reference: '0.2001080415-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ppxp-tcltk is vulnerable in Debian 3.1.\nUpgrade to ppxp-tcltk_0.2001080415-10sarge2\n');
}
if (deb_check(prefix: 'ppxp-x11', release: '3.1', reference: '0.2001080415-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ppxp-x11 is vulnerable in Debian 3.1.\nUpgrade to ppxp-x11_0.2001080415-10sarge2\n');
}
if (deb_check(prefix: 'ppxp', release: '3.1', reference: '0.2001080415-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ppxp is vulnerable in Debian sarge.\nUpgrade to ppxp_0.2001080415-10sarge2\n');
}
if (deb_check(prefix: 'ppxp', release: '3.0', reference: '0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ppxp is vulnerable in Debian woody.\nUpgrade to ppxp_0\n');
}
if (w) { security_hole(port: 0, data: desc); }
