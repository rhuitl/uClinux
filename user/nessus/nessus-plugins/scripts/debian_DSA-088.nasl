# This script was automatically generated from the dsa-088
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The fml (a mailing list package) as distributed in Debian GNU/Linux 2.2
suffers from a cross-site scripting problem. When generating index
pages for list archives the `<\' and `>\' characters were not properly
escaped for subjects.

This has been fixed in version 3.0+beta.20000106-5, and we recommend
that you upgrade your fml package to that version. Upgrading will
automatically regenerate the index pages.



Solution : http://www.debian.org/security/2001/dsa-088
Risk factor : High';

if (description) {
 script_id(14925);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "088");
 script_bugtraq_id(3623);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA088] DSA-088-1 fml");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-088-1 fml");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'fml', release: '2.2', reference: '3.0+beta.20000106-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fml is vulnerable in Debian 2.2.\nUpgrade to fml_3.0+beta.20000106-5\n');
}
if (w) { security_hole(port: 0, data: desc); }
