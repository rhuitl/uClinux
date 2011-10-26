# This script was automatically generated from the dsa-033
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = 'The author of analog, Stephen Turner, has found a buffer
overflow bug in all versions of analog except of version 4.16.  A malicious
user could use an ALIAS command to construct very long strings which were not
checked for length and boundaries.  This bug is particularly dangerous if the
form interface (which allows unknown users to run the program via a CGI script)
has been installed.  There doesn\'t seem to be a known exploit.

The bugfix has been backported to the version of analog from Debian
2.2.  Version 4.01-1potato1 is fixed.

We recommend you upgrade your analog packages immediately.


Solution : http://www.debian.org/security/2001/dsa-033
Risk factor : High';

if (description) {
 script_id(14870);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "033");
 script_cve_id("CVE-2001-0301");
 script_bugtraq_id(2377);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA033] DSA-033-1 analog");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-033-1 analog");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'analog', release: '2.2', reference: '4.01-1potato1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package analog is vulnerable in Debian 2.2.\nUpgrade to analog_4.01-1potato1\n');
}
if (w) { security_hole(port: 0, data: desc); }
