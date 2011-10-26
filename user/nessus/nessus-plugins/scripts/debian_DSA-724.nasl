# This script was automatically generated from the dsa-724
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Maksymilian Arciemowicz discovered several cross site scripting issues
in phpsysinfo, a PHP based host information application.
For the stable distribution (woody) these problems have been fixed in
version 2.0-3woody2.
For the testing (sarge) and unstable (sid) distribution these problems
have been fixed in version 2.3-3.
We recommend that you upgrade your phpsysinfo package.


Solution : http://www.debian.org/security/2005/dsa-724
Risk factor : High';

if (description) {
 script_id(18303);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "724");
 script_cve_id("CVE-2005-0870");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA724] DSA-724-1 phpsysinfo");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-724-1 phpsysinfo");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'phpsysinfo', release: '3.0', reference: '2.0-3woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpsysinfo is vulnerable in Debian 3.0.\nUpgrade to phpsysinfo_2.0-3woody2\n');
}
if (deb_check(prefix: 'phpsysinfo', release: '3.0', reference: '2.0-3woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpsysinfo is vulnerable in Debian woody.\nUpgrade to phpsysinfo_2.0-3woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
