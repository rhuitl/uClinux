# This script was automatically generated from the dsa-769
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Szymon Zygmunt and Michal Bartoszkiewicz discovered a memory alignment
error in libgadu (from ekg, console Gadu Gadu client, an instant
messaging program) which is included in gaim, a multi-protocol instant
messaging client, as well.  This can not be exploited on the x86
architecture but on others, e.g. on Sparc and lead to a bus error,
in other words a denial of service.
The old stable distribution (woody) does not seem to be affected by
this problem.
For the stable distribution (sarge) this problem has been fixed in
version 1.2.1-1.4.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you upgrade your gaim package.


Solution : http://www.debian.org/security/2005/dsa-769
Risk factor : High';

if (description) {
 script_id(19318);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "769");
 script_cve_id("CVE-2005-2370");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA769] DSA-769-1 gaim");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-769-1 gaim");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gaim', release: '3.1', reference: '1.2.1-1.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gaim is vulnerable in Debian 3.1.\nUpgrade to gaim_1.2.1-1.4\n');
}
if (deb_check(prefix: 'gaim-data', release: '3.1', reference: '1.2.1-1.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gaim-data is vulnerable in Debian 3.1.\nUpgrade to gaim-data_1.2.1-1.4\n');
}
if (deb_check(prefix: 'gaim-dev', release: '3.1', reference: '1.2.1-1.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gaim-dev is vulnerable in Debian 3.1.\nUpgrade to gaim-dev_1.2.1-1.4\n');
}
if (deb_check(prefix: 'gaim', release: '3.1', reference: '1.2.1-1.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gaim is vulnerable in Debian sarge.\nUpgrade to gaim_1.2.1-1.4\n');
}
if (w) { security_hole(port: 0, data: desc); }
