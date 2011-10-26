# This script was automatically generated from the dsa-040
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = 'Bill Nottingham reported a problem in the
wrapping/unwrapping functions of the slrn newsreader. A long header in a
message might overflow a buffer, which could result in executing arbitrary
code encoded in the message.

The default configuration does not have wrapping enable, but it can easily
be enabled either by changing the configuration or pressing W while viewing a
message.

This has been fixed in version 0.9.6.2-9potato1 and we recommand that you
upgrade your slrn package immediately.


Solution : http://www.debian.org/security/2001/dsa-040
Risk factor : High';

if (description) {
 script_id(14877);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "040");
 script_cve_id("CVE-2001-0441");
 script_bugtraq_id(2493);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA040] DSA-040-1 slrn");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-040-1 slrn");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'slrn', release: '2.2', reference: '0.9.6.2-9potato1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package slrn is vulnerable in Debian 2.2.\nUpgrade to slrn_0.9.6.2-9potato1\n');
}
if (deb_check(prefix: 'slrnpull', release: '2.2', reference: '0.9.6.2-9potato1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package slrnpull is vulnerable in Debian 2.2.\nUpgrade to slrnpull_0.9.6.2-9potato1\n');
}
if (w) { security_hole(port: 0, data: desc); }
