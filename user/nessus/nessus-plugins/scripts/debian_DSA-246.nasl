# This script was automatically generated from the dsa-246
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The developers of tomcat discovered several problems in tomcat version
3.x.  The Common Vulnerabilities and Exposures project identifies the
following problems:
For the stable distribution (woody) this problem has been fixed in
version 3.3a-4woody.1.
The old stable distribution (potato) does not contain tomcat packages.
For the unstable distribution (sid) this problem has been fixed in
version 3.3.1a-1.
We recommend that you upgrade your tomcat package.


Solution : http://www.debian.org/security/2003/dsa-246
Risk factor : High';

if (description) {
 script_id(15083);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "246");
 script_cve_id("CVE-2003-0042", "CVE-2003-0043", "CVE-2003-0044");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA246] DSA-246-1 tomcat");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-246-1 tomcat");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libapache-mod-jk', release: '3.0', reference: '3.3a-4woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapache-mod-jk is vulnerable in Debian 3.0.\nUpgrade to libapache-mod-jk_3.3a-4woody1\n');
}
if (deb_check(prefix: 'tomcat', release: '3.0', reference: '3.3a-4woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tomcat is vulnerable in Debian 3.0.\nUpgrade to tomcat_3.3a-4woody1\n');
}
if (deb_check(prefix: 'tomcat', release: '3.1', reference: '3.3.1a-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tomcat is vulnerable in Debian 3.1.\nUpgrade to tomcat_3.3.1a-1\n');
}
if (deb_check(prefix: 'tomcat', release: '3.0', reference: '3.3a-4woody.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tomcat is vulnerable in Debian woody.\nUpgrade to tomcat_3.3a-4woody.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
