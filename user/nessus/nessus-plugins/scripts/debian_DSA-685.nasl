# This script was automatically generated from the dsa-685
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
version 21.2-1woody3.
For the unstable distribution (sid) these problems have been fixed in
version 21.3+1-9.
We recommend that you upgrade your emacs packages.


Solution : http://www.debian.org/security/2005/dsa-685
Risk factor : High';

if (description) {
 script_id(17130);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "685");
 script_cve_id("CVE-2005-0100");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA685] DSA-685-1 emacs21");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-685-1 emacs21");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'emacs21', release: '3.0', reference: '21.2-1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package emacs21 is vulnerable in Debian 3.0.\nUpgrade to emacs21_21.2-1woody3\n');
}
if (deb_check(prefix: 'emacs21-el', release: '3.0', reference: '21.2-1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package emacs21-el is vulnerable in Debian 3.0.\nUpgrade to emacs21-el_21.2-1woody3\n');
}
if (deb_check(prefix: 'emacs21', release: '3.1', reference: '21.3+1-9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package emacs21 is vulnerable in Debian 3.1.\nUpgrade to emacs21_21.3+1-9\n');
}
if (deb_check(prefix: 'emacs21', release: '3.0', reference: '21.2-1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package emacs21 is vulnerable in Debian woody.\nUpgrade to emacs21_21.2-1woody3\n');
}
if (w) { security_hole(port: 0, data: desc); }
