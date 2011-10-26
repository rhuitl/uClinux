# This script was automatically generated from the dsa-102
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
zen-parse found a bug in the current implementation of at which leads
into a heap corruption vulnerability which in turn could potentially
lead into an exploit of the daemon user.
We recommend that you upgrade your at packages.
Unfortunately, the bugfix from DSA 102-1 wasn\'t propagated properly due
to a packaging bug.  While the file parsetime.y was fixed, and yy.tab.c
should be generated from it, yy.tab.c from the original source was still
used.  This has been fixed in DSA-102-2.


Solution : http://www.debian.org/security/2002/dsa-102
Risk factor : High';

if (description) {
 script_id(14939);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "102");
 script_cve_id("CVE-2002-0004");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA102] DSA-102-2 at");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-102-2 at");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'at', release: '2.2', reference: '3.1.8-10.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package at is vulnerable in Debian 2.2.\nUpgrade to at_3.1.8-10.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
