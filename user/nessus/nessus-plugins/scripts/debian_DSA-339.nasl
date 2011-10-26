# This script was automatically generated from the dsa-339
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
NOTE: due to a combination of administrative problems, this advisory
was erroneously released with the identifier "DSA-337-1".  DSA-337-1
correctly refers to an earlier advisory regarding gtksee.
semi, a MIME library for GNU Emacs, does not take appropriate
security precautions when creating temporary files.  This bug could
potentially be exploited to overwrite arbitrary files with the
privileges of the user running Emacs and semi, potentially with
contents supplied by the attacker.
wemi is a fork of semi, and contains the same bug.
For the stable distribution (woody) this problem has been fixed in
semi version 1.14.3.cvs.2001.08.10-1woody2 and wemi version
1.14.0.20010802wemiko-1.3.
For the unstable distribution (sid) this problem has been fixed in
semi version 1.14.5+20030609-1.  The unstable distribution does not
contain a wemi package.
We recommend that you update your semi and wemi packages.


Solution : http://www.debian.org/security/2003/dsa-339
Risk factor : High';

if (description) {
 script_id(15176);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "339");
 script_cve_id("CVE-2003-0440");
 script_bugtraq_id(8115);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA339] DSA-339-1 semi");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-339-1 semi");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'semi', release: '3.0', reference: '1.14.3.cvs.2001.08.10-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package semi is vulnerable in Debian 3.0.\nUpgrade to semi_1.14.3.cvs.2001.08.10-1woody2\n');
}
if (deb_check(prefix: 'wemi', release: '3.0', reference: '1.14.0.20010802wemiko-1.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package wemi is vulnerable in Debian 3.0.\nUpgrade to wemi_1.14.0.20010802wemiko-1.3\n');
}
if (deb_check(prefix: 'semi', release: '3.1', reference: '1.14.5+20030609-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package semi is vulnerable in Debian 3.1.\nUpgrade to semi_1.14.5+20030609-1\n');
}
if (deb_check(prefix: 'semi', release: '3.0', reference: '1.14.3.cvs.2001.08')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package semi is vulnerable in Debian woody.\nUpgrade to semi_1.14.3.cvs.2001.08\n');
}
if (w) { security_hole(port: 0, data: desc); }
