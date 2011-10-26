# This script was automatically generated from the dsa-161
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A problem with user privileges has been discovered in the Mantis
package, a PHP based bug tracking system.  The Mantis system didn\'t
check whether a user is permitted to view a bug, but displays it right
away if the user entered a valid bug id.
Another bug in Mantis caused the \'View Bugs\' page to list bugs from
both public and private projects when no projects are accessible to
the current user.
These problems have been fixed in version 0.17.1-2.5 for the current
stable distribution (woody) and in version 0.17.5-2 for the unstable
distribution (sid).  The old stable distribution (potato) is not
affected, since it doesn\'t contain the mantis package.
Additional information:
We recommend that you upgrade your mantis packages.


Solution : http://www.debian.org/security/2002/dsa-161
Risk factor : High';

if (description) {
 script_id(14998);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "161");
 script_cve_id("CVE-2002-1115", "CVE-2002-1116");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA161] DSA-161-1 mantis");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-161-1 mantis");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mantis', release: '3.0', reference: '0.17.1-2.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mantis is vulnerable in Debian 3.0.\nUpgrade to mantis_0.17.1-2.5\n');
}
if (w) { security_hole(port: 0, data: desc); }
