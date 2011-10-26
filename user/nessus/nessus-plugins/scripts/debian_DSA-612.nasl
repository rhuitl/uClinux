# This script was automatically generated from the dsa-612
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Rudolf Polzer discovered a vulnerability in a2ps, a converter and
pretty-printer for many formats to PostScript.  The program did not
escape shell meta characters properly which could lead to the
execution of arbitrary commands as a privileged user if a2ps is
installed as a printer filter.
For the stable distribution (woody) this problem has been fixed in
version 4.13b-16woody1.
For the unstable distribution (sid) this problem has been fixed in
version 1:4.13b-4.2.
We recommend that you upgrade your a2ps package.


Solution : http://www.debian.org/security/2004/dsa-612
Risk factor : High';

if (description) {
 script_id(16008);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "612");
 script_cve_id("CVE-2004-1170");
 script_bugtraq_id(11025);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA612] DSA-612-1 a2ps");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-612-1 a2ps");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'a2ps', release: '3.0', reference: '4.13b-16woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package a2ps is vulnerable in Debian 3.0.\nUpgrade to a2ps_4.13b-16woody1\n');
}
if (deb_check(prefix: 'a2ps', release: '3.1', reference: '4.13b-4.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package a2ps is vulnerable in Debian 3.1.\nUpgrade to a2ps_4.13b-4.2\n');
}
if (deb_check(prefix: 'a2ps', release: '3.0', reference: '4.13b-16woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package a2ps is vulnerable in Debian woody.\nUpgrade to a2ps_4.13b-16woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
