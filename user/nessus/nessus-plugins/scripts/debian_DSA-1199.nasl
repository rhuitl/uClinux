# This script was automatically generated from the dsa-1199
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several vulnerabilities have been identified in webmin, a web-based
administration toolkit. The Common Vulnerabilities and Exposures project
identifies the following vulnerabilities:
	A format string vulnerability in miniserv.pl could allow an
	attacker to cause a denial of service by crashing the
	application or exhausting system resources, and could
	potentially allow arbitrary code execution.
	Improper input sanitization in miniserv.pl could allow an
	attacker to read arbitrary files on the webmin host by providing
	a specially crafted URL path to the miniserv http server.
	Improper handling of null characters in URLs in miniserv.pl
	could allow an attacker to conduct cross-site scripting attacks,
	read CGI program source code, list local directories, and
	potentially execute arbitrary code.
Stable updates are available for alpha, amd64, arm, hppa, i386, ia64,
m68k, mips, mipsel, powerpc, s390 and sparc.
For the stable distribution (sarge), these problems have been fixed in
version 1.180-3sarge1.
Webmin is not included in unstable (sid) or testing (etch), so these
problems are not present.
We recommend that you upgrade your webmin (1.180-3sarge1) package.


Solution : http://www.debian.org/security/2006/dsa-1199
Risk factor : High';

if (description) {
 script_id(22908);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1199");
 script_cve_id("CVE-2005-3912", "CVE-2006-3392", "CVE-2006-4542");
 script_bugtraq_id(15629, 18744, 19820);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1199] DSA-1199-1 webmin");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1199-1 webmin");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'webmin', release: '3.1', reference: '1.180-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webmin is vulnerable in Debian 3.1.\nUpgrade to webmin_1.180-3sarge1\n');
}
if (deb_check(prefix: 'webmin-core', release: '3.1', reference: '1.180-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webmin-core is vulnerable in Debian 3.1.\nUpgrade to webmin-core_1.180-3sarge1\n');
}
if (deb_check(prefix: 'webmin', release: '3.1', reference: '1.180-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webmin is vulnerable in Debian sarge.\nUpgrade to webmin_1.180-3sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
