# This script was automatically generated from the dsa-093
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Wietse Venema reported he found a denial of service vulnerability in
postfix. The SMTP session log that postfix keeps for debugging purposes
could grow to an unreasonable size.

This has been fixed in version 0.0.19991231pl11-2.



Solution : http://www.debian.org/security/2001/dsa-093
Risk factor : High';

if (description) {
 script_id(14930);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "093");
 script_cve_id("CVE-2001-0894");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA093] DSA-093-1 postfix");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-093-1 postfix");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'postfix', release: '2.2', reference: '0.0.19991231pl11-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package postfix is vulnerable in Debian 2.2.\nUpgrade to postfix_0.0.19991231pl11-2\n');
}
if (w) { security_hole(port: 0, data: desc); }
