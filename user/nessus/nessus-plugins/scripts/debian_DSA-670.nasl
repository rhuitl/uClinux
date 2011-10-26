# This script was automatically generated from the dsa-670
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Max Vozeler discovered several format string vulnerabilities in the
movemail utility of Emacs, the well-known editor.  Via connecting to a
malicious POP server an attacker can execute arbitrary code under the
privileges of group mail.
For the stable distribution (woody) these problems have been fixed in
version 20.7-13.3.
The unstable distribution (sid) does not contain an Emacs20 package
anymore.
We recommend that you upgrade your emacs packages.


Solution : http://www.debian.org/security/2005/dsa-670
Risk factor : High';

if (description) {
 script_id(16344);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "670");
 script_cve_id("CVE-2005-0100");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA670] DSA-670-1 emacs20");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-670-1 emacs20");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'emacs20', release: '3.0', reference: '20.7-13.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package emacs20 is vulnerable in Debian 3.0.\nUpgrade to emacs20_20.7-13.3\n');
}
if (deb_check(prefix: 'emacs20-el', release: '3.0', reference: '20.7-13.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package emacs20-el is vulnerable in Debian 3.0.\nUpgrade to emacs20-el_20.7-13.3\n');
}
if (deb_check(prefix: 'emacs20', release: '3.0', reference: '20.7-13.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package emacs20 is vulnerable in Debian woody.\nUpgrade to emacs20_20.7-13.3\n');
}
if (w) { security_hole(port: 0, data: desc); }
