# This script was automatically generated from the dsa-802
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Marcus Meissner discovered that the cvsbug program from CVS, which
serves the popular Concurrent Versions System, uses temporary files in
an insecure fashion.
For the old stable distribution (woody) this problem has been fixed in
version 1.11.1p1debian-13.
In the stable distribution (sarge) the cvs package does not expose the
cvsbug program anymore.
In the unstable distribution (sid) the cvs package does not expose the
cvsbug program anymore.
We recommend that you upgrade your cvs package.


Solution : http://www.debian.org/security/2005/dsa-802
Risk factor : High';

if (description) {
 script_id(19609);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "802");
 script_cve_id("CVE-2005-2693");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA802] DSA-802-1 cvs");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-802-1 cvs");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'cvs', release: '3.0', reference: '1.11.1p1debian-13')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cvs is vulnerable in Debian 3.0.\nUpgrade to cvs_1.11.1p1debian-13\n');
}
if (deb_check(prefix: 'cvs', release: '3.0', reference: '1.11.1p1debian-13')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cvs is vulnerable in Debian woody.\nUpgrade to cvs_1.11.1p1debian-13\n');
}
if (w) { security_hole(port: 0, data: desc); }
