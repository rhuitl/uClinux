# This script was automatically generated from the dsa-927
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The last update of tkdiff contained a programming error which is
fixed by this version.  For completeness we\'re adding the original
advisory text:
Javier Fernández-Sanguino Peña from the Debian Security Audit project
discovered that tkdiff, a graphical side by side "diff" utility,
creates temporary files in an insecure fashion.
For the old stable distribution (woody) this problem has been fixed in
version 3.08-3woody1.
For the stable distribution (sarge) this problem has been fixed in
version 4.0.2-1sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 4.0.2-4.
We recommend that you upgrade your tkdiff package.


Solution : http://www.debian.org/security/2005/dsa-927
Risk factor : High';

if (description) {
 script_id(22793);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "927");
 script_cve_id("CVE-2005-3343");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA927] DSA-927-2 tkdiff");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-927-2 tkdiff");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'tkdiff', release: '', reference: '4.0.2-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tkdiff is vulnerable in Debian .\nUpgrade to tkdiff_4.0.2-4\n');
}
if (deb_check(prefix: 'tkdiff', release: '3.0', reference: '3.08-3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tkdiff is vulnerable in Debian 3.0.\nUpgrade to tkdiff_3.08-3woody1\n');
}
if (deb_check(prefix: 'tkdiff', release: '3.1', reference: '4.0.2-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tkdiff is vulnerable in Debian 3.1.\nUpgrade to tkdiff_4.0.2-1sarge1\n');
}
if (deb_check(prefix: 'tkdiff', release: '3.1', reference: '4.0.2-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tkdiff is vulnerable in Debian sarge.\nUpgrade to tkdiff_4.0.2-1sarge1\n');
}
if (deb_check(prefix: 'tkdiff', release: '3.0', reference: '3.08-3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tkdiff is vulnerable in Debian woody.\nUpgrade to tkdiff_3.08-3woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
