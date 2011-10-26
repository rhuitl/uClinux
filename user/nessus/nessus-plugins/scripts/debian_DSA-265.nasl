# This script was automatically generated from the dsa-265
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Rémi Perrot fixed several security related bugs in the bonsai, the
Mozilla CVS query tool by web interface.  Vulnerabilities include
arbitrary code execution, cross-site scripting and access to
configuration parameters.  The Common Vulnerabilities and Exposures
project identifies the following problems:
For the stable distribution (woody) these problems have been fixed in
version 1.3+cvs20020224-1woody1.
The old stable distribution (potato) is not affected since it doesn\'t
contain bonsai.
For the unstable distribution (sid) these problems have been fixed in
version 1.3+cvs20030317-1.
We recommend that you upgrade your bonsai package.


Solution : http://www.debian.org/security/2003/dsa-265
Risk factor : High';

if (description) {
 script_id(15102);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "265");
 script_cve_id("CVE-2003-0152", "CVE-2003-0153", "CVE-2003-0154", "CVE-2003-0155");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA265] DSA-265-1 bonsai");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-265-1 bonsai");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'bonsai', release: '3.0', reference: '1.3+cvs20020224-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bonsai is vulnerable in Debian 3.0.\nUpgrade to bonsai_1.3+cvs20020224-1woody1\n');
}
if (deb_check(prefix: 'bonsai', release: '3.1', reference: '1.3+cvs20030317-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bonsai is vulnerable in Debian 3.1.\nUpgrade to bonsai_1.3+cvs20030317-1\n');
}
if (deb_check(prefix: 'bonsai', release: '3.0', reference: '1.3+cvs20020224-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bonsai is vulnerable in Debian woody.\nUpgrade to bonsai_1.3+cvs20020224-1woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
