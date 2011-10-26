# This script was automatically generated from the dsa-953
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several cross-site scripting vulnerabilities have been discovered in
flyspray, a lightweight bug tracking system, which allows attackers to
insert arbitary script code into the index page.
The old stable distribution (woody) does not contain flyspray.
For the stable distribution (sarge) this problem has been fixed in
version 0.9.7-2.1.
For the testing (etch) and unstable distribution (sid) this problem has
been fixed in version 0.9.8-5.
We recommend that you upgrade your flyspray package.


Solution : http://www.debian.org/security/2006/dsa-953
Risk factor : High';

if (description) {
 script_id(22819);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "953");
 script_cve_id("CVE-2005-3334");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA953] DSA-953-1 flyspray");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-953-1 flyspray");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'flyspray', release: '3.1', reference: '0.9.7-2.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package flyspray is vulnerable in Debian 3.1.\nUpgrade to flyspray_0.9.7-2.1\n');
}
if (deb_check(prefix: 'flyspray', release: '3.1', reference: '0.9.7-2.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package flyspray is vulnerable in Debian sarge.\nUpgrade to flyspray_0.9.7-2.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
