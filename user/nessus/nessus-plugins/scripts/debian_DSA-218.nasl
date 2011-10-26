# This script was automatically generated from the dsa-218
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A cross site scripting vulnerability has been reported for Bugzilla, a
web-based bug tracking system.  Bugzilla does not properly sanitize
any input submitted by users for use in quips.  As a result, it is possible for a
remote attacker to create a malicious link containing script code
which will be executed in the browser of a legitimate user, in the
context of the website running Bugzilla.  This issue may be exploited
to steal cookie-based authentication credentials from legitimate users
of the website running the vulnerable software.
This vulnerability only affects users who have the \'quips\' feature
enabled and who upgraded from version 2.10 which did not exist inside
of Debian.  The Debian package history of Bugzilla starts with 1.13
and jumped to 2.13.  However, users could have installed version 2.10
prior to the Debian package.
For the current stable distribution (woody) this problem has been
fixed in version 2.14.2-0woody3.
The old stable distribution (potato) does not contain a Bugzilla
package.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you upgrade your bugzilla packages.


Solution : http://www.debian.org/security/2002/dsa-218
Risk factor : High';

if (description) {
 script_id(15055);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "218");
 script_bugtraq_id(6257);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA218] DSA-218-1 bugzilla");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-218-1 bugzilla");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'bugzilla', release: '3.0', reference: '2.14.2-0woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bugzilla is vulnerable in Debian 3.0.\nUpgrade to bugzilla_2.14.2-0woody3\n');
}
if (deb_check(prefix: 'bugzilla-doc', release: '3.0', reference: '2.14.2-0woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bugzilla-doc is vulnerable in Debian 3.0.\nUpgrade to bugzilla-doc_2.14.2-0woody3\n');
}
if (deb_check(prefix: 'bugzilla', release: '3.0', reference: '2.14.2-0woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bugzilla is vulnerable in Debian woody.\nUpgrade to bugzilla_2.14.2-0woody3\n');
}
if (w) { security_hole(port: 0, data: desc); }
