# This script was automatically generated from the dsa-342
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
mozart, a development platform based on the Oz language, includes MIME
configuration data which specifies that Oz applications should be
passed to the Oz interpreter for execution.  This means that file
managers, web browsers, and other programs which honor the mailcap
file could automatically execute Oz programs downloaded from untrusted
sources.  Thus, a malicious Oz program could execute arbitrary code
under the uid of a user running a MIME-aware client program if the
user selected a file (for example, choosing a link in a web browser).
For the stable distribution (woody) this problem has been fixed in
version 1.2.3.20011204-3woody1.
For the unstable distribution (sid) this problem has been fixed in
version 1.2.5.20030212-2.
We recommend that you update your mozart package.


Solution : http://www.debian.org/security/2003/dsa-342
Risk factor : High';

if (description) {
 script_id(15179);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "342");
 script_cve_id("CVE-2003-0538");
 script_bugtraq_id(8125);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA342] DSA-342-1 mozart");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-342-1 mozart");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mozart', release: '3.0', reference: '1.2.3.20011204-3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozart is vulnerable in Debian 3.0.\nUpgrade to mozart_1.2.3.20011204-3woody1\n');
}
if (deb_check(prefix: 'mozart-contrib', release: '3.0', reference: '1.2.3.20011204-3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozart-contrib is vulnerable in Debian 3.0.\nUpgrade to mozart-contrib_1.2.3.20011204-3woody1\n');
}
if (deb_check(prefix: 'mozart-doc-html', release: '3.0', reference: '1.2.3.20011204-3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozart-doc-html is vulnerable in Debian 3.0.\nUpgrade to mozart-doc-html_1.2.3.20011204-3woody1\n');
}
if (deb_check(prefix: 'mozart', release: '3.1', reference: '1.2.5.20030212-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozart is vulnerable in Debian 3.1.\nUpgrade to mozart_1.2.5.20030212-2\n');
}
if (deb_check(prefix: 'mozart', release: '3.0', reference: '1.2.3.20011204-3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozart is vulnerable in Debian woody.\nUpgrade to mozart_1.2.3.20011204-3woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
