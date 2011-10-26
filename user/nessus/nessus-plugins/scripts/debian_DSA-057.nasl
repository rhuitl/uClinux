# This script was automatically generated from the dsa-057
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The gftp package as distributed with Debian GNU/Linux 2.2 has a problem
in its logging code: it logged data received from the network but it did
not protect itself from printf format attacks. An attacker can use this
by making an FTP server return special responses that exploit this.

This has been fixed in version 2.0.6a-3.1, and we recommend that you
upgrade your gftp package.

Note: this advisory was posted as DSA-055-1 by mistake.



Solution : http://www.debian.org/security/2001/dsa-057
Risk factor : High';

if (description) {
 script_id(14894);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "057");
 script_cve_id("CVE-2001-0489");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA057] DSA-057-1 gftp");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-057-1 gftp");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gftp', release: '2.2', reference: '2.0.6a-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gftp is vulnerable in Debian 2.2.\nUpgrade to gftp_2.0.6a-3.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
