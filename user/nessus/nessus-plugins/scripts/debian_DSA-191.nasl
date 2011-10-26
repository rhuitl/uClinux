# This script was automatically generated from the dsa-191
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several cross site scripting vulnerabilities have been found in
squirrelmail, a feature-rich webmail package written in PHP4.  The
Common Vulnerabilities and Exposures (CVE) project identified the
following vulnerabilities:
These problems have been fixed in version 1.2.6-1.1 for the current stable
distribution (woody) and in version 1.2.8-1.1 for the unstable
distribution (sid).  The old stable distribution (potato) is not
affected since it doesn\'t contain a squirrelmail package.
We recommend that you upgrade your squirrelmail package.


Solution : http://www.debian.org/security/2002/dsa-191
Risk factor : High';

if (description) {
 script_id(15028);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "191");
 script_cve_id("CVE-2002-1131", "CVE-2002-1132", "CVE-2002-1276");
 script_bugtraq_id(5763, 5949);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA191] DSA-191-1 squirrelmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-191-1 squirrelmail");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'squirrelmail', release: '3.0', reference: '1.2.6-1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squirrelmail is vulnerable in Debian 3.0.\nUpgrade to squirrelmail_1.2.6-1.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
