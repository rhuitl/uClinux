# This script was automatically generated from the dsa-1090
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A vulnerability has been discovered in SpamAssassin, a Perl-based spam
filter using text analysis, that can allow remote attackers to execute
arbitrary commands.  This problem only affects systems where spamd is
reachable via the internet and used with vpopmail virtual users, via
the "-v" / "--vpopmail" switch, and with the "-P" / "--paranoid"
switch which is not the default setting on Debian.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 3.0.3-2sarge1.
For the volatile archive for the stable distribution (sarge) this
problem has been fixed in version 3.1.0a-0volatile3.
For the unstable distribution (sid) this problem has been fixed in
version 3.1.3-1.
We recommend that you upgrade your spamd package.


Solution : http://www.debian.org/security/2006/dsa-1090
Risk factor : High';

if (description) {
 script_id(22632);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1090");
 script_cve_id("CVE-2006-2447");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1090] DSA-1090-1 spamassassin");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1090-1 spamassassin");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'spamassassin', release: '', reference: '3.1.3-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package spamassassin is vulnerable in Debian .\nUpgrade to spamassassin_3.1.3-1\n');
}
if (deb_check(prefix: 'spamassassin', release: '3.1', reference: '3.0.3-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package spamassassin is vulnerable in Debian 3.1.\nUpgrade to spamassassin_3.0.3-2sarge1\n');
}
if (deb_check(prefix: 'spamc', release: '3.1', reference: '3.0.3-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package spamc is vulnerable in Debian 3.1.\nUpgrade to spamc_3.0.3-2sarge1\n');
}
if (deb_check(prefix: 'spamassassin', release: '3.1', reference: '3.1.0a-0volatile3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package spamassassin is vulnerable in Debian sarge.\nUpgrade to spamassassin_3.1.0a-0volatile3\n');
}
if (w) { security_hole(port: 0, data: desc); }
