# This script was automatically generated from the dsa-638
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
"jaguar" has discovered two security relevant problems in gopherd, the
Gopher server in Debian which is part of the gopher package.  The
Common Vulnerabilities and Exposures project identifies the following
vulnerabilities:
    An integer overflow can happen when posting content of a specially
    calculated size.
    A format string vulnerability has been found in the log routine.
For the stable distribution (woody) these problems have been fixed in
version 3.0.3woody2.
The unstable distribution (sid) does not contain a gopherd package.
It has been replaced by Pygopherd.
We recommend that you upgrade your gopherd package.


Solution : http://www.debian.org/security/2005/dsa-638
Risk factor : High';

if (description) {
 script_id(16156);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "638");
 script_cve_id("CVE-2004-0560", "CVE-2004-0561");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA638] DSA-638-1 gopher");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-638-1 gopher");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gopher', release: '3.0', reference: '3.0.3woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gopher is vulnerable in Debian 3.0.\nUpgrade to gopher_3.0.3woody2\n');
}
if (deb_check(prefix: 'gopherd', release: '3.0', reference: '3.0.3woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gopherd is vulnerable in Debian 3.0.\nUpgrade to gopherd_3.0.3woody2\n');
}
if (deb_check(prefix: 'gopher', release: '3.0', reference: '3.0.3woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gopher is vulnerable in Debian woody.\nUpgrade to gopher_3.0.3woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
