# This script was automatically generated from the dsa-713
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several bugs have been found in junkbuster, a HTTP proxy and filter.
The Common Vulnerability and Exposures project identifies the
following vulnerabilities:
    James Ranson discovered that an attacker can modify the referrer
    setting with a carefully crafted URL by accidentally overwriting a
    global variable.
    Tavis Ormandy from the Gentoo Security Team discovered several
    heap corruptions due to inconsistent use of an internal function
    that can crash the daemon or possibly lead to the execution of
    arbitrary code.
For the stable distribution (woody) these problems have been fixed in
version 2.0.2-0.2woody1.
The unstable distribution (sid) doesn\'t contain the junkbuster package
anymore.
We recommend that you upgrade your junkbuster package.


Solution : http://www.debian.org/security/2005/dsa-713
Risk factor : High';

if (description) {
 script_id(18115);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "713");
 script_cve_id("CVE-2005-1108", "CVE-2005-1109");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA713] DSA-713-1 junkbuster");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-713-1 junkbuster");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'junkbuster', release: '3.0', reference: '2.0.2-0.2woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package junkbuster is vulnerable in Debian 3.0.\nUpgrade to junkbuster_2.0.2-0.2woody1\n');
}
if (deb_check(prefix: 'junkbuster', release: '3.0', reference: '2.0.2-0.2woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package junkbuster is vulnerable in Debian woody.\nUpgrade to junkbuster_2.0.2-0.2woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
