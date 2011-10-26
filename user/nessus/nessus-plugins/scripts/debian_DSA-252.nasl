# This script was automatically generated from the dsa-252
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A problem has been discovered in slocate, a secure locate replacement.
A buffer overflow in the setgid program slocate can be used to execute
arbitrary code as group slocate.  This can be used to alter the
slocate database.
For the stable distribution (woody) this problem has been
fixed in version 2.6-1.3.1.
The old stable distribution (potato) is not affected by this problem.
For the unstable distribution (sid) this problem has been fixed in
version 2.7-1.
We recommend that you upgrade your slocate package immediately.


Solution : http://www.debian.org/security/2003/dsa-252
Risk factor : High';

if (description) {
 script_id(15089);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "252");
 script_cve_id("CVE-2003-0056");
 script_bugtraq_id(6676);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA252] DSA-252-1 slocate");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-252-1 slocate");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'slocate', release: '3.0', reference: '2.6-1.3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package slocate is vulnerable in Debian 3.0.\nUpgrade to slocate_2.6-1.3.1\n');
}
if (deb_check(prefix: 'slocate', release: '3.1', reference: '2.7-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package slocate is vulnerable in Debian 3.1.\nUpgrade to slocate_2.7-1\n');
}
if (deb_check(prefix: 'slocate', release: '3.0', reference: '2.6-1.3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package slocate is vulnerable in Debian woody.\nUpgrade to slocate_2.6-1.3.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
