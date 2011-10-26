# This script was automatically generated from the dsa-058
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Megyer Laszlo found a printf format bug in the exim mail transfer
agent. The code that checks the header syntax of an email logs
an error without protecting itself against printf format attacks.
It\'s only exploitable locally with the -bS switch
(in batched SMTP mode).

This problem has been fixed in version 3.12-10.1. Since that code is
not turned on by default a standard installation is not vulnerable,
but we still recommend to upgrade your exim package.



Solution : http://www.debian.org/security/2001/dsa-058
Risk factor : High';

if (description) {
 script_id(14895);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "058");
 script_cve_id("CVE-2001-0690");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA058] DSA-058-1 exim");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-058-1 exim");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'exim', release: '2.2', reference: '3.12-10.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package exim is vulnerable in Debian 2.2.\nUpgrade to exim_3.12-10.1\n');
}
if (deb_check(prefix: 'eximon', release: '2.2', reference: '3.12-10.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package eximon is vulnerable in Debian 2.2.\nUpgrade to eximon_3.12-10.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
