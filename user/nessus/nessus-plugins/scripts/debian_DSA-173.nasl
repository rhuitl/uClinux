# This script was automatically generated from the dsa-173
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The developers of Bugzilla, a web-based bug tracking system,
discovered a problem in the handling of more than 47 groups.  When a
new product is added to an installation with 47 groups or more and
"usebuggroups" is enabled, the new group will be assigned a groupset
bit using Perl math that is not exact beyond 248.
This results in
the new group being defined with a "bit" that has several bits set.
As users are given access to the new group, those users will also gain
access to spurious lower group privileges.  Also, group bits were not
always reused when groups were deleted.
This problem has been fixed in version 2.14.2-0woody2 for the current
stable distribution (woody) and will soon be fixed in the unstable
distribution (sid).  The old stable distribution (potato) doesn\'t
contain a bugzilla package.
We recommend that you upgrade your bugzilla package.


Solution : http://www.debian.org/security/2002/dsa-173
Risk factor : High';

if (description) {
 script_id(15010);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "173");
 script_cve_id("CVE-2002-1196");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA173] DSA-173-1 bugzilla");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-173-1 bugzilla");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'bugzilla', release: '3.0', reference: '2.14.2-0woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bugzilla is vulnerable in Debian 3.0.\nUpgrade to bugzilla_2.14.2-0woody2\n');
}
if (deb_check(prefix: 'bugzilla-doc', release: '3.0', reference: '2.14.2-0woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bugzilla-doc is vulnerable in Debian 3.0.\nUpgrade to bugzilla-doc_2.14.2-0woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
