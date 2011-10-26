# This script was automatically generated from the dsa-662
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Andrew Archibald discovered that the last update to squirrelmail which
was intended to fix several problems caused a regression which got
exposed when the user hits a session timeout.  For completeness below
is the original advisory text:
Several vulnerabilities have been discovered in Squirrelmail, a
commonly used webmail system.  The Common Vulnerabilities and
Exposures project identifies the following problems:
    Upstream developers noticed that an unsanitised variable could
    lead to cross site scripting.
    Grant Hollingworth discovered that under certain circumstances URL
    manipulation could lead to the execution of arbitrary code with
    the privileges of www-data.  This problem only exists in version
    1.2.6 of Squirrelmail.
For the stable distribution (woody) these problems have been fixed in
version 1.2.6-3.
For the unstable distribution (sid) the problem that affects unstable
has been fixed in version 1.4.4-1.
We recommend that you upgrade your squirrelmail package.


Solution : http://www.debian.org/security/2005/dsa-662
Risk factor : High';

if (description) {
 script_id(16283);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "662");
 script_cve_id("CVE-2005-0104", "CVE-2005-0152");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA662] DSA-662-2 squirrelmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-662-2 squirrelmail");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'squirrelmail', release: '3.0', reference: '1.2.6-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squirrelmail is vulnerable in Debian 3.0.\nUpgrade to squirrelmail_1.2.6-3\n');
}
if (deb_check(prefix: 'squirrelmail', release: '3.1', reference: '1.4.4-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squirrelmail is vulnerable in Debian 3.1.\nUpgrade to squirrelmail_1.4.4-1\n');
}
if (deb_check(prefix: 'squirrelmail', release: '3.0', reference: '1.2.6-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squirrelmail is vulnerable in Debian woody.\nUpgrade to squirrelmail_1.2.6-3\n');
}
if (w) { security_hole(port: 0, data: desc); }
