# This script was automatically generated from the dsa-112
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A set of buffer overflow problems have been found in hanterm, a Hangul
terminal for X11 derived from xterm, that will read and display Korean
characters in its terminal window.  The font handling code in hanterm
uses hard limited string variables but didn\'t check for boundaries.
This problem can be exploited by a malicious user to gain access to
the utmp group which is able to write the wtmp and utmp files.  These
files record login and logout activities.
This problem has been fixed in version 3.3.1p17-5.2 for the stable
Debian distribution.  A fixed package for the current testing/unstable
distribution is not yet available but will have a version number
higher than 3.3.1p18-6.1.
We recommend that you upgrade your hanterm packages immediately if you
have them installed.  Known exploits are already available.


Solution : http://www.debian.org/security/2002/dsa-112
Risk factor : High';

if (description) {
 script_id(14949);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "112");
 script_cve_id("CVE-2002-0239");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA112] DSA-112-1 hanterm");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-112-1 hanterm");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'hanterm', release: '2.2', reference: '3.3.1p17-5.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hanterm is vulnerable in Debian 2.2.\nUpgrade to hanterm_3.3.1p17-5.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
