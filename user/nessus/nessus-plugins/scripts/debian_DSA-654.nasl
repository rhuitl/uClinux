# This script was automatically generated from the dsa-654
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Erik Sjölund has discovered several security relevant problems in
enscript, a program to convert ASCII text into Postscript and other
formats.  The Common Vulnerabilities and Exposures project identifies
the following vulnerabilities:
    Unsanitised input can cause the execution of arbitrary commands
    via EPSF pipe support.  This has been disabled, also upstream.
    Due to missing sanitising of filenames it is possible that a
    specially crafted filename can cause arbitrary commands to be
    executed.
    Multiple buffer overflows can cause the program to crash.
Usually, enscript is only run locally, but since it is executed inside
of viewcvs some of the problems mentioned above can easily be turned
into a remote vulnerability.
For the stable distribution (woody) these problems have been fixed in
version 1.6.3-1.3.
For the unstable distribution (sid) these problems have been fixed in
version 1.6.4-6.
We recommend that you upgrade your enscript package.


Solution : http://www.debian.org/security/2005/dsa-654
Risk factor : High';

if (description) {
 script_id(16238);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "654");
 script_cve_id("CVE-2004-1184", "CVE-2004-1185", "CVE-2004-1186");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA654] DSA-654-1 enscript");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-654-1 enscript");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'enscript', release: '3.0', reference: '1.6.3-1.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package enscript is vulnerable in Debian 3.0.\nUpgrade to enscript_1.6.3-1.3\n');
}
if (deb_check(prefix: 'enscript', release: '3.1', reference: '1.6.4-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package enscript is vulnerable in Debian 3.1.\nUpgrade to enscript_1.6.4-6\n');
}
if (deb_check(prefix: 'enscript', release: '3.0', reference: '1.6.3-1.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package enscript is vulnerable in Debian woody.\nUpgrade to enscript_1.6.3-1.3\n');
}
if (w) { security_hole(port: 0, data: desc); }
