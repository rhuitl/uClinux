# This script was automatically generated from the dsa-1033
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several remote vulnerabilities have been discovered in the Horde web
application framework, which may lead to the execution of arbitrary 
web script code. The Common Vulnerabilities and Exposures project
identifies the following problems:
    Several Cross-Site-Scripting vulnerabilities have been discovered in
    the "share edit window".
    Null characters in the URL parameter bypass a sanity check, which
    allowed remote attackers to read arbitrary files, which allowed
    information disclosure.
    User input in the help viewer was passed unsanitised to the eval()
    function, which allowed injection of arbitrary web code.
The old stable distribution (woody) doesn\'t contain horde3 packages.
For the stable distribution (sarge) these problems have been fixed in
version 3.0.4-4sarge3.
For the unstable distribution (sid) these problems have been fixed in
version 3.1.1-1.
We recommend that you upgrade your horde3 package.


Solution : http://www.debian.org/security/2006/dsa-1033
Risk factor : High';

if (description) {
 script_id(22575);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1033");
 script_cve_id("CVE-2005-4190", "CVE-2006-1260", "CVE-2006-1491");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1033] DSA-1033-1 horde3");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1033-1 horde3");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'horde3', release: '', reference: '3.1.1-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package horde3 is vulnerable in Debian .\nUpgrade to horde3_3.1.1-1\n');
}
if (deb_check(prefix: 'horde3', release: '3.1', reference: '3.0.4-4sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package horde3 is vulnerable in Debian 3.1.\nUpgrade to horde3_3.0.4-4sarge3\n');
}
if (deb_check(prefix: 'horde3', release: '3.1', reference: '3.0.4-4sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package horde3 is vulnerable in Debian sarge.\nUpgrade to horde3_3.0.4-4sarge3\n');
}
if (w) { security_hole(port: 0, data: desc); }
