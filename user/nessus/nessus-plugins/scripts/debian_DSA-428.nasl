# This script was automatically generated from the dsa-428
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A vulnerability was discovered in slocate, a program to index and
search for files, whereby a specially crafted database could overflow
a heap-based buffer.  This vulnerability could be exploited by a local
attacker to gain the privileges of the "slocate" group, which can
access the global database containing a list of pathnames of all files
on the system, including those which should only be visible to
privileged users.
This problem, and a category of potential similar problems, have been
fixed by modifying slocate to drop privileges before reading a
user-supplied database.
For the current stable distribution (woody) this problem has been
fixed in version 2.6-1.3.2.
For the unstable distribution (sid) this problem will be fixed soon.
Refer to Debian bug #226103 
for status information.
We recommend that you update your slocate package.


Solution : http://www.debian.org/security/2004/dsa-428
Risk factor : High';

if (description) {
 script_id(15265);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "428");
 script_cve_id("CVE-2003-0848");
 script_bugtraq_id(8780);
 script_xref(name: "CERT", value: "441956");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA428] DSA-428-1 slocate");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-428-1 slocate");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'slocate', release: '3.0', reference: '2.6-1.3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package slocate is vulnerable in Debian 3.0.\nUpgrade to slocate_2.6-1.3.2\n');
}
if (deb_check(prefix: 'slocate', release: '3.0', reference: '2.6-1.3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package slocate is vulnerable in Debian woody.\nUpgrade to slocate_2.6-1.3.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
