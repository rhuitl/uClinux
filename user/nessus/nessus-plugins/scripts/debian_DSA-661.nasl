# This script was automatically generated from the dsa-661
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Dan McMahill noticed that our advisory DSA 661-1 did not correct
the multiple insecure files problem, hence, this update. For
completeness below is the original advisory text:
Javier Fernández-Sanguino Peña from the Debian Security Audit project
discovered that f2c and fc, which are both part of the f2c package, a
fortran 77 to C/C++ translator, open temporary files insecurely and
are hence vulnerable to a symlink attack.  The Common
Vulnerabilities and Exposures project identifies the following
vulnerabilities:
    Multiple insecure temporary files in the f2c translator.
    Two insecure temporary files in the f2 shell script.
For the stable distribution (woody) and all others including testing
this problem has been fixed in version 20010821-3.2.
We recommend that you upgrade your f2c package.


Solution : http://www.debian.org/security/2005/dsa-661
Risk factor : High';

if (description) {
 script_id(16266);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "661");
 script_cve_id("CVE-2005-0017", "CVE-2005-0018");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA661] DSA-661-2 f2c");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-661-2 f2c");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'f2c', release: '3.0', reference: '20010821-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package f2c is vulnerable in Debian 3.0.\nUpgrade to f2c_20010821-3.2\n');
}
if (deb_check(prefix: 'f2c', release: '3.0', reference: '20010821-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package f2c is vulnerable in Debian woody.\nUpgrade to f2c_20010821-3.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
