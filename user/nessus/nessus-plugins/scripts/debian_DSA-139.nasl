# This script was automatically generated from the dsa-139
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
GOBBLES found an insecure use of format strings in the super package.
The included program super is intended to provide access to certain
system users for particular users and programs, similar to the program
sudo.  Exploiting this format string vulnerability a local user can
gain unauthorized root access.
This problem has been fixed in version 3.12.2-2.1 for the old stable
distribution (potato), in version 3.16.1-1.1 for the current stable
distribution (woody) and in version 3.18.0-3 for the unstable
distribution (sid).
We recommend that you upgrade your super package immediately.


Solution : http://www.debian.org/security/2002/dsa-139
Risk factor : High';

if (description) {
 script_id(14976);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "139");
 script_cve_id("CVE-2002-0817");
 script_bugtraq_id(5367);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA139] DSA-139-1 super");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-139-1 super");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'super', release: '2.2', reference: '3.12.2-2.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package super is vulnerable in Debian 2.2.\nUpgrade to super_3.12.2-2.1\n');
}
if (deb_check(prefix: 'super', release: '3.0', reference: '3.16.1-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package super is vulnerable in Debian 3.0.\nUpgrade to super_3.16.1-1.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
