# This script was automatically generated from the dsa-673
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Max Vozeler discovered an integer overflow in a helper application
inside of Evolution, a free groupware suite.  A local attacker could
cause the setuid root helper to execute arbitrary code with elevated
privileges.
For the stable distribution (woody) this problem has been fixed in
version 1.0.5-1woody2.
For the unstable distribution (sid) this problem has been fixed in
version 2.0.3-1.2.
We recommend that you upgrade your evolution package.


Solution : http://www.debian.org/security/2005/dsa-673
Risk factor : High';

if (description) {
 script_id(16347);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "673");
 script_cve_id("CVE-2005-0102");
 script_bugtraq_id(12354);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA673] DSA-673-1 evolution");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-673-1 evolution");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'evolution', release: '3.0', reference: '1.0.5-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package evolution is vulnerable in Debian 3.0.\nUpgrade to evolution_1.0.5-1woody2\n');
}
if (deb_check(prefix: 'libcamel-dev', release: '3.0', reference: '1.0.5-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libcamel-dev is vulnerable in Debian 3.0.\nUpgrade to libcamel-dev_1.0.5-1woody2\n');
}
if (deb_check(prefix: 'libcamel0', release: '3.0', reference: '1.0.5-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libcamel0 is vulnerable in Debian 3.0.\nUpgrade to libcamel0_1.0.5-1woody2\n');
}
if (deb_check(prefix: 'evolution', release: '3.1', reference: '2.0.3-1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package evolution is vulnerable in Debian 3.1.\nUpgrade to evolution_2.0.3-1.2\n');
}
if (deb_check(prefix: 'evolution', release: '3.0', reference: '1.0.5-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package evolution is vulnerable in Debian woody.\nUpgrade to evolution_1.0.5-1woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
