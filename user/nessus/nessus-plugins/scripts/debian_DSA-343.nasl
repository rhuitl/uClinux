# This script was automatically generated from the dsa-343
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
skk (Simple Kana to Kanji conversion program), does not take
appropriate security precautions when creating temporary files.  This
bug could potentially be exploited to overwrite arbitrary files with
the privileges of the user running Emacs and skk.
ddskk is derived from the same code, and contains the same bug.
For the stable distribution (woody) this problem has been fixed in
skk version 10.62a-4woody1 and ddskk version 11.6.rel.0-2woody1.
For the unstable distribution (sid) this problem has been fixed in
ddskk version 12.1.cvs.20030622-1, and skk will be fixed soon.
We recommend that you update your skk and ddskk packages.


Solution : http://www.debian.org/security/2003/dsa-343
Risk factor : High';

if (description) {
 script_id(15180);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "343");
 script_cve_id("CVE-2003-0539");
 script_bugtraq_id(8144);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA343] DSA-343-1 skk, ddskk");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-343-1 skk, ddskk");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'ddskk', release: '3.0', reference: '11.6.rel.0-2woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ddskk is vulnerable in Debian 3.0.\nUpgrade to ddskk_11.6.rel.0-2woody1\n');
}
if (deb_check(prefix: 'skk', release: '3.0', reference: '10.62a-4woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package skk is vulnerable in Debian 3.0.\nUpgrade to skk_10.62a-4woody1\n');
}
if (deb_check(prefix: 'skkserv', release: '3.0', reference: '10.62a-4woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package skkserv is vulnerable in Debian 3.0.\nUpgrade to skkserv_10.62a-4woody1\n');
}
if (deb_check(prefix: 'ddskk', release: '3.1', reference: '12.1.cvs')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ddskk is vulnerable in Debian 3.1.\nUpgrade to ddskk_12.1.cvs\n');
}
if (deb_check(prefix: 'skk', release: '3.0', reference: '10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package skk is vulnerable in Debian woody.\nUpgrade to skk_10\n');
}
if (w) { security_hole(port: 0, data: desc); }
