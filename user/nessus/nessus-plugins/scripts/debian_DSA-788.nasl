# This script was automatically generated from the dsa-788
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several security related problems have been discovered in kismet, a
wireless 802.11b monitoring tool.  The Common Vulnerabilities and
Exposures project identifies the following problems:
    Insecure handling of unprintable characters in the SSID.
    Multiple integer underflows could allow remote attackers to
    execute arbitrary code.
The old stable distribution (woody) does not seem to be affected by
these problems.
For the stable distribution (sarge) these problems have been fixed in
version 2005.04.R1-1sarge1.
For the unstable distribution (sid) these problems have been fixed in
version 2005.08.R1-1.
We recommend that you upgrade your kismet package.


Solution : http://www.debian.org/security/2005/dsa-788
Risk factor : High';

if (description) {
 script_id(19531);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "788");
 script_cve_id("CVE-2005-2626", "CVE-2005-2627");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA788] DSA-788-1 kismet");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-788-1 kismet");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'kismet', release: '', reference: '2005.08')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kismet is vulnerable in Debian .\nUpgrade to kismet_2005.08\n');
}
if (deb_check(prefix: 'kismet', release: '3.1', reference: '2005.04.R1-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kismet is vulnerable in Debian 3.1.\nUpgrade to kismet_2005.04.R1-1sarge1\n');
}
if (deb_check(prefix: 'kismet', release: '3.1', reference: '2005.04')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kismet is vulnerable in Debian sarge.\nUpgrade to kismet_2005.04\n');
}
if (w) { security_hole(port: 0, data: desc); }
