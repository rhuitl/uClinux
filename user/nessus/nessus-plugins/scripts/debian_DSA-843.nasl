# This script was automatically generated from the dsa-843
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Two vulnerabilities have been discovered in the ARC archive program
under Unix.  The Common Vulnerabilities and Exposures project
identifies the following problems:
    Eric Romang discovered that the ARC archive program under Unix
    creates a temporary file with insecure permissions which may lead
    to an attacker stealing sensitive information.
    Joey Schulze discovered that the temporary file was created in an
    insecure fashion as well, leaving it open to a classic symlink
    attack.
The old stable distribution (woody) does not contain arc packages.
For the stable distribution (sarge) these problems have been fixed in
version 5.21l-1sarge1.
For the unstable distribution (sid) these problems have been fixed in
version 5.21m-1.
We recommend that you upgrade your arc package.


Solution : http://www.debian.org/security/2005/dsa-843
Risk factor : High';

if (description) {
 script_id(19847);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "843");
 script_cve_id("CVE-2005-2945", "CVE-2005-2992");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA843] DSA-843-1 arc");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-843-1 arc");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'arc', release: '', reference: '5.21m-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package arc is vulnerable in Debian .\nUpgrade to arc_5.21m-1\n');
}
if (deb_check(prefix: 'arc', release: '3.1', reference: '5.21l-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package arc is vulnerable in Debian 3.1.\nUpgrade to arc_5.21l-1sarge1\n');
}
if (deb_check(prefix: 'arc', release: '3.1', reference: '5.21l-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package arc is vulnerable in Debian sarge.\nUpgrade to arc_5.21l-1sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
