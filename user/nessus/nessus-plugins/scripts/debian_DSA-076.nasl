# This script was automatically generated from the dsa-076
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Pavel Machek has found a buffer overflow in the `most\' pager program.
The problem is part of most\'s tab expansion where the program would
write beyond the bounds two array variables when viewing a malicious
file.  This could lead into other data structures being overwritten
which in turn could enable most to execute arbitrary code being able
to compromise the users environment.

This has been fixed in the upstream version 4.9.2 and an updated
version of 4.9.0 for Debian GNU/Linux 2.2.

We recommend that you upgrade your most package immediately.



Solution : http://www.debian.org/security/2001/dsa-076
Risk factor : High';

if (description) {
 script_id(14913);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "076");
 script_cve_id("CVE-2001-0961");
 script_bugtraq_id(3347);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA076] DSA-076-1 most");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-076-1 most");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'most', release: '2.2', reference: '4.9.0-2.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package most is vulnerable in Debian 2.2.\nUpgrade to most_4.9.0-2.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
