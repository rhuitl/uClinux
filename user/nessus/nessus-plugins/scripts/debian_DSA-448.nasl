# This script was automatically generated from the dsa-448
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Multiple vulnerabilities were discovered in pwlib, a library used to
aid in writing portable applications, whereby a remote attacker could
cause a denial of service or potentially execute arbitrary code.  This
library is most notably used in several applications implementing the
H.323 teleconferencing protocol, including the OpenH323 suite,
gnomemeeting and asterisk.
For the current stable distribution (woody) this problem has been
fixed in version 1.2.5-5woody1.
For the unstable distribution (sid), this problem will be fixed soon.
Refer to Debian Bug#233888 for details.
We recommend that you update your pwlib package.


Solution : http://www.debian.org/security/2004/dsa-448
Risk factor : High';

if (description) {
 script_id(15285);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "448");
 script_cve_id("CVE-2004-0097");
 script_bugtraq_id(9406);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA448] DSA-448-1 pwlib");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-448-1 pwlib");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'asnparser', release: '3.0', reference: '1.2.5-5woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package asnparser is vulnerable in Debian 3.0.\nUpgrade to asnparser_1.2.5-5woody1\n');
}
if (deb_check(prefix: 'libpt-1.2.0', release: '3.0', reference: '1.2.5-5woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpt-1.2.0 is vulnerable in Debian 3.0.\nUpgrade to libpt-1.2.0_1.2.5-5woody1\n');
}
if (deb_check(prefix: 'libpt-dbg', release: '3.0', reference: '1.2.5-5woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpt-dbg is vulnerable in Debian 3.0.\nUpgrade to libpt-dbg_1.2.5-5woody1\n');
}
if (deb_check(prefix: 'libpt-dev', release: '3.0', reference: '1.2.5-5woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpt-dev is vulnerable in Debian 3.0.\nUpgrade to libpt-dev_1.2.5-5woody1\n');
}
if (deb_check(prefix: 'pwlib', release: '3.0', reference: '1.2.5-5woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pwlib is vulnerable in Debian woody.\nUpgrade to pwlib_1.2.5-5woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
