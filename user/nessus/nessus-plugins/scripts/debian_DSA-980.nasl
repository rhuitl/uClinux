# This script was automatically generated from the dsa-980
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Joxean Koret discovered several security problems in tutos, a web-based
team organization software. The Common Vulnerabilities and Exposures Project
identifies the following problems:
     An SQL injection vulnerability allows the execution of SQL commands
     through the link_id parameter in file_overview.php.
     Cross-Site-Scripting vulnerabilities in the search function of the
     address book and in app_new.php allow the execution of web script
     code.
The old stable distribution (woody) does not contain tutos packages.
For the stable distribution (sarge) these problems have been fixed in
version 1.1.20031017-2+1sarge1.
The unstable distribution (sid) does no longer contain tutos packages.
We recommend that you upgrade your tutos package.


Solution : http://www.debian.org/security/2006/dsa-980
Risk factor : High';

if (description) {
 script_id(22846);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "980");
 script_cve_id("CVE-2004-2161", "CVE-2004-2162");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA980] DSA-980-1 tutos");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-980-1 tutos");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'tutos', release: '3.1', reference: '1.1.20031017-2+1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tutos is vulnerable in Debian 3.1.\nUpgrade to tutos_1.1.20031017-2+1sarge1\n');
}
if (deb_check(prefix: 'tutos', release: '3.1', reference: '1.1.20031017-2+1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tutos is vulnerable in Debian sarge.\nUpgrade to tutos_1.1.20031017-2+1sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
