# This script was automatically generated from the dsa-396
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several vulnerabilities have been discovered in thttpd, a tiny HTTP
server.
The Common Vulnerabilities and Exposures project identifies the
following vulnerabilities:
  Marcus Breiing discovered that if thttpd it is used for virtual
  hosting, and an attacker supplies a specially crafted &ldquo;Host:&rdquo;
  header with a pathname instead of a hostname, thttpd will reveal
  information about the host system.  Hence, an attacker can browse
  the entire disk.
  Joel Söderberg and Christer Öberg discovered a remote overflow which
  allows an attacker to partially overwrite the EBP register and
  hence execute arbitrary code.
For the stable distribution (woody) these problems have been fixed in
version 2.21b-11.2.
For the unstable distribution (sid) these problems have been fixed in
version 2.23beta1-2.3.
We recommend that you upgrade your thttpd package immediately.


Solution : http://www.debian.org/security/2003/dsa-396
Risk factor : High';

if (description) {
 script_id(15233);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "396");
 script_cve_id("CVE-2002-1562", "CVE-2003-0899");
 script_bugtraq_id(8906, 8924);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA396] DSA-396-1 thttpd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-396-1 thttpd");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'thttpd', release: '3.0', reference: '2.21b-11.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package thttpd is vulnerable in Debian 3.0.\nUpgrade to thttpd_2.21b-11.2\n');
}
if (deb_check(prefix: 'thttpd-util', release: '3.0', reference: '2.21b-11.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package thttpd-util is vulnerable in Debian 3.0.\nUpgrade to thttpd-util_2.21b-11.2\n');
}
if (deb_check(prefix: 'thttpd', release: '3.1', reference: '2.23beta1-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package thttpd is vulnerable in Debian 3.1.\nUpgrade to thttpd_2.23beta1-2.3\n');
}
if (deb_check(prefix: 'thttpd', release: '3.0', reference: '2.21b-11.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package thttpd is vulnerable in Debian woody.\nUpgrade to thttpd_2.21b-11.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
