# This script was automatically generated from the dsa-1165
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Lionel Elie Mamane discovered a security vulnerability in
capi4hylafax, tools for faxing over a CAPI 2.0 device, that allows
remote attackers to execute arbitrary commands on the fax receiving
system.
For the stable distribution (sarge) this problem has been fixed in
version 01.02.03-10sarge2.
For the unstable distribution (sid) this problem has been fixed in
version 01.03.00.99.svn.300-3.
We recommend that you upgrade your capi4hylafax package.


Solution : http://www.debian.org/security/2006/dsa-1165
Risk factor : High';

if (description) {
 script_id(22707);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1165");
 script_cve_id("CVE-2006-3126");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1165] DSA-1165-1 capi4hylafax");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1165-1 capi4hylafax");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'capi4hylafax', release: '', reference: '01.03.00.99.svn.300-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package capi4hylafax is vulnerable in Debian .\nUpgrade to capi4hylafax_01.03.00.99.svn.300-3\n');
}
if (deb_check(prefix: 'capi4hylafax', release: '3.1', reference: '01.02.03-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package capi4hylafax is vulnerable in Debian 3.1.\nUpgrade to capi4hylafax_01.02.03-10sarge2\n');
}
if (deb_check(prefix: 'capi4hylafax', release: '3.1', reference: '01.02.03-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package capi4hylafax is vulnerable in Debian sarge.\nUpgrade to capi4hylafax_01.02.03-10sarge2\n');
}
if (w) { security_hole(port: 0, data: desc); }
