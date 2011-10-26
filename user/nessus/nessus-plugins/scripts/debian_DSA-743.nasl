# This script was automatically generated from the dsa-743
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several problems have been discovered in ht, a viewer, editor and
analyser for various executables, that may lead to the execution of
arbitrary code.  The Common Vulnerabilities and Exposures project
identifies the following problems:
    Tavis Ormandy of the Gentoo Linux Security Team discovered an
    integer overflow in the ELF parser.
    The authors have discovered a buffer overflow in the PE parser.
For the old stable distribution (woody) these problems have been fixed
in version 0.5.0-1woody4.  For the HP Precision architecture, you are
advised not to use this package anymore since we cannot provide
updated packages as it doesn\'t compile anymore.
For the stable distribution (sarge) these problems have been fixed in
version 0.8.0-2sarge4.
For the unstable distribution (sid) these problems have been fixed in
version 0.8.0-3.
We recommend that you upgrade your ht package.


Solution : http://www.debian.org/security/2005/dsa-743
Risk factor : High';

if (description) {
 script_id(18651);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "743");
 script_cve_id("CVE-2005-1545", "CVE-2005-1546");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA743] DSA-743-1 ht");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-743-1 ht");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'ht', release: '', reference: '0.8.0-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ht is vulnerable in Debian .\nUpgrade to ht_0.8.0-3\n');
}
if (deb_check(prefix: 'ht', release: '3.0', reference: '0.5.0-1woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ht is vulnerable in Debian 3.0.\nUpgrade to ht_0.5.0-1woody4\n');
}
if (deb_check(prefix: 'ht', release: '3.1', reference: '0.8.0-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ht is vulnerable in Debian 3.1.\nUpgrade to ht_0.8.0-2sarge4\n');
}
if (deb_check(prefix: 'ht', release: '3.1', reference: '0.8.0-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ht is vulnerable in Debian sarge.\nUpgrade to ht_0.8.0-2sarge4\n');
}
if (deb_check(prefix: 'ht', release: '3.0', reference: '0.5.0-1woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ht is vulnerable in Debian woody.\nUpgrade to ht_0.5.0-1woody4\n');
}
if (w) { security_hole(port: 0, data: desc); }
