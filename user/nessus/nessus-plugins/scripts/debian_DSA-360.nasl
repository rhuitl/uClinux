# This script was automatically generated from the dsa-360
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
xfstt, a TrueType font server for the X window system was found to
contain two classes of vulnerabilities:
  CVE-2003-0581: a remote attacker could send requests crafted to
  trigger any of several buffer overruns, causing a denial of service or
  possibly executing arbitrary code on the server with the privileges
  of the "nobody" user.
  CVE-2003-0625: certain invalid data sent during the connection
  handshake could allow a remote attacker to read certain regions of
  memory belonging to the xfstt process.  This information could be
  used for fingerprinting, or to aid in exploitation of a different
  vulnerability.
For the current stable distribution (woody) these problems have been
fixed in version 1.2.1-3.
For the unstable distribution (sid), CVE-2003-0581 is fixed in xfstt
1.5-1, and CVE-2003-0625 will be fixed soon.
We recommend that you update your xfstt package.


Solution : http://www.debian.org/security/2003/dsa-360
Risk factor : High';

if (description) {
 script_id(15197);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "360");
 script_cve_id("CVE-2003-0581", "CVE-2003-0625");
 script_bugtraq_id(8182, 8255);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA360] DSA-360-1 xfstt");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-360-1 xfstt");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'xfstt', release: '3.0', reference: '1.2.1-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xfstt is vulnerable in Debian 3.0.\nUpgrade to xfstt_1.2.1-3\n');
}
if (deb_check(prefix: 'xfstt', release: '3.0', reference: '1.2.1-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xfstt is vulnerable in Debian woody.\nUpgrade to xfstt_1.2.1-3\n');
}
if (w) { security_hole(port: 0, data: desc); }
