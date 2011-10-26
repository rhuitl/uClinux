# This script was automatically generated from the dsa-285
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Karol Lewandowski discovered that psbanner, a printer filter that
creates a PostScript format banner and is part of LPRng, insecurely
creates a temporary file for debugging purpose when it is configured
as filter.  The program does not check whether this file already
exists or is linked to another place, psbanner writes its current environment
and called arguments to the file unconditionally with the user id
daemon.
For the stable distribution (woody) this problem has been fixed in
version 3.8.10-1.2.
The old stable distribution (potato) is not affected by this problem.
For the unstable distribution (sid) this problem has been fixed in
version 3.8.20-4.
We recommend that you upgrade your lprng package.


Solution : http://www.debian.org/security/2003/dsa-285
Risk factor : High';

if (description) {
 script_id(15122);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "285");
 script_cve_id("CVE-2003-0136");
 script_bugtraq_id(7334);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA285] DSA-285-1 lprng");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-285-1 lprng");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'lprng', release: '3.0', reference: '3.8.10-1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lprng is vulnerable in Debian 3.0.\nUpgrade to lprng_3.8.10-1.2\n');
}
if (deb_check(prefix: 'lprng-doc', release: '3.0', reference: '3.8.10-1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lprng-doc is vulnerable in Debian 3.0.\nUpgrade to lprng-doc_3.8.10-1.2\n');
}
if (deb_check(prefix: 'lprng', release: '3.1', reference: '3.8.20-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lprng is vulnerable in Debian 3.1.\nUpgrade to lprng_3.8.20-4\n');
}
if (deb_check(prefix: 'lprng', release: '3.0', reference: '3.8.10-1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lprng is vulnerable in Debian woody.\nUpgrade to lprng_3.8.10-1.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
