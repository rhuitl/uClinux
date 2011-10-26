# This script was automatically generated from the dsa-154
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A flaw
was discovered in FAM\'s group handling.  In the effect users
are unable to read FAM directories they have group read and execute
permissions on.  However, also unprivileged users can potentially
learn names of files that only users in root\'s group should be able to
view.
This problem been fixed in version 2.6.6.1-5.2 for the current stable
stable distribution (woody) and in version 2.6.8-1 (or any later
version) for the unstable distribution (sid).  The old stable
distribution (potato) is not affected, since it doesn\'t contain fam
packages.
We recommend that you upgrade your fam packages.


Solution : http://www.debian.org/security/2002/dsa-154
Risk factor : High';

if (description) {
 script_id(14991);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "154");
 script_cve_id("CVE-2002-0875");
 script_bugtraq_id(5487);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA154] DSA-154-1 fam");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-154-1 fam");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'fam', release: '3.0', reference: '2.6.6.1-5.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fam is vulnerable in Debian 3.0.\nUpgrade to fam_2.6.6.1-5.2\n');
}
if (deb_check(prefix: 'libfam-dev', release: '3.0', reference: '2.6.6.1-5.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libfam-dev is vulnerable in Debian 3.0.\nUpgrade to libfam-dev_2.6.6.1-5.2\n');
}
if (deb_check(prefix: 'libfam0', release: '3.0', reference: '2.6.6.1-5.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libfam0 is vulnerable in Debian 3.0.\nUpgrade to libfam0_2.6.6.1-5.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
