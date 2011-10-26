# This script was automatically generated from the dsa-736
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A vulnerability was recently found in the way that SpamAssassin parses
certain email headers. This vulnerability could cause SpamAssassin to
consume a large number of CPU cycles when processing messages containing
these headers, leading to a potential denial of service (DOS) attack. 
The version of SpamAssassin in the old stable distribution (woody) is
not vulnerable.
For the stable distribution (sarge), this problem has been fixed in
version 3.0.3-2. Note that packages are not yet ready for certain
architectures; these will be released as they become available.
For the unstable distribution (sid), this problem has been fixed in
version 3.0.4-1.
We recommend that you upgrade your sarge or sid spamassassin package.


Solution : http://www.debian.org/security/2005/dsa-736
Risk factor : High';

if (description) {
 script_id(18596);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "736");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA736] DSA-736-1 spamassassin");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-736-1 spamassassin");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'spamassassin', release: '', reference: '3.0.4-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package spamassassin is vulnerable in Debian .\nUpgrade to spamassassin_3.0.4-1\n');
}
if (deb_check(prefix: 'spamassassin', release: '3.1', reference: '3.0.3-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package spamassassin is vulnerable in Debian 3.1.\nUpgrade to spamassassin_3.0.3-2\n');
}
if (deb_check(prefix: 'spamc', release: '3.1', reference: '3.0.3-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package spamc is vulnerable in Debian 3.1.\nUpgrade to spamc_3.0.3-2\n');
}
if (deb_check(prefix: 'spamassassin', release: '3.1', reference: '3.0.3-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package spamassassin is vulnerable in Debian sarge.\nUpgrade to spamassassin_3.0.3-2\n');
}
if (w) { security_hole(port: 0, data: desc); }
