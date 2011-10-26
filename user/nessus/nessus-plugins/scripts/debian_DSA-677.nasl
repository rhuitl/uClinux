# This script was automatically generated from the dsa-677
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Erik Sjölund discovered that a support script of sympa, a mailing list
manager, is running setuid sympa and vulnerable to a buffer overflow.
This could potentially lead to the execution of arbitrary code under
the sympa user id.
For the stable distribution (woody) this problem has been fixed in
version 3.3.3-3woody2.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you upgrade your sympa package.


Solution : http://www.debian.org/security/2005/dsa-677
Risk factor : High';

if (description) {
 script_id(16381);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "677");
 script_cve_id("CVE-2005-0073");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA677] DSA-677-1 sympa");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-677-1 sympa");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'sympa', release: '3.0', reference: '3.3.3-3woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sympa is vulnerable in Debian 3.0.\nUpgrade to sympa_3.3.3-3woody2\n');
}
if (deb_check(prefix: 'wwsympa', release: '3.0', reference: '3.3.3-3woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package wwsympa is vulnerable in Debian 3.0.\nUpgrade to wwsympa_3.3.3-3woody2\n');
}
if (deb_check(prefix: 'sympa', release: '3.0', reference: '3.3.3-3woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sympa is vulnerable in Debian woody.\nUpgrade to sympa_3.3.3-3woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
