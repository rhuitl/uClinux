# This script was automatically generated from the dsa-064
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
SecureNet Service reported that w3m (a console web browser) has a
buffer overflow in its MIME header parsing code. This could be exploited
by an attacker if by making a web-server a user visits return carefully
crafted MIME headers.

This has been fixed in version 0.1.10+0.1.11pre+kokb23-4, and we
recommend that you upgrade your w3m package.



Solution : http://www.debian.org/security/2001/dsa-064
Risk factor : High';

if (description) {
 script_id(14901);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "064");
 script_cve_id("CVE-2001-0700");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA064] DSA-064-1 w3m");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-064-1 w3m");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'w3m', release: '2.2', reference: '0.1.10+0.1.11pre+kokb23-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package w3m is vulnerable in Debian 2.2.\nUpgrade to w3m_0.1.10+0.1.11pre+kokb23-4\n');
}
if (w) { security_hole(port: 0, data: desc); }
