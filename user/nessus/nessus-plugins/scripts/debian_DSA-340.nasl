# This script was automatically generated from the dsa-340
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
NOTE: due to a combination of administrative problems, this advisory
was erroneously released with the identifier "DSA-338-1".  DSA-338-1
correctly refers to an earlier advisory regarding proftpd.
x-face-el, a decoder for images included inline in X-Face email
headers, does not take appropriate security precautions when creating
temporary files.  This bug could potentially be exploited to overwrite
arbitrary files with the privileges of the user running Emacs and
x-face-el, potentially with contents supplied by the attacker.
For the stable distribution (woody) this problem has been fixed in
version 1.3.6.19-1woody1.
For the unstable distribution (sid) this problem has been fixed in
version 1.3.6.23-1.
We recommend that you update your x-face-el package.


Solution : http://www.debian.org/security/2003/dsa-340
Risk factor : High';

if (description) {
 script_id(15177);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "340");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA340] DSA-340-1 x-face-el");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-340-1 x-face-el");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'x-face-el', release: '3.0', reference: '1.3.6.19-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package x-face-el is vulnerable in Debian 3.0.\nUpgrade to x-face-el_1.3.6.19-1woody1\n');
}
if (deb_check(prefix: 'x-face-el', release: '3.1', reference: '1.3.6.23-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package x-face-el is vulnerable in Debian 3.1.\nUpgrade to x-face-el_1.3.6.23-1\n');
}
if (deb_check(prefix: 'x-face-el', release: '3.0', reference: '1.3.6.19-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package x-face-el is vulnerable in Debian woody.\nUpgrade to x-face-el_1.3.6.19-1woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
