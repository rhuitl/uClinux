# This script was automatically generated from the dsa-225
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A security vulnerability has been confirmed to exist in Apache Tomcat
4.0.x releases, which allows to use a specially crafted URL to return
the unprocessed source of a JSP page, or, under special circumstances,
a static resource which would otherwise have been protected by a
security constraint, without the need for being properly
authenticated.  This is based on a variant of the exploit that was
identified as CVE-2002-1148.
For the current stable distribution (woody) this problem has been
fixed in version 4.0.3-3woody2.
The old stable distribution (potato) does not contain tomcat packages.
For the unstable distribution (sid) this problem does not exist in the
current version 4.1.16-1.
We recommend that you upgrade your tomcat packages.


Solution : http://www.debian.org/security/2003/dsa-225
Risk factor : High';

if (description) {
 script_id(15062);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "225");
 script_cve_id("CVE-2002-1394");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA225] DSA-225-1 tomcat4");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-225-1 tomcat4");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libtomcat4-java', release: '3.0', reference: '4.0.3-3woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtomcat4-java is vulnerable in Debian 3.0.\nUpgrade to libtomcat4-java_4.0.3-3woody2\n');
}
if (deb_check(prefix: 'tomcat4', release: '3.0', reference: '4.0.3-3woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tomcat4 is vulnerable in Debian 3.0.\nUpgrade to tomcat4_4.0.3-3woody2\n');
}
if (deb_check(prefix: 'tomcat4-webapps', release: '3.0', reference: '4.0.3-3woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tomcat4-webapps is vulnerable in Debian 3.0.\nUpgrade to tomcat4-webapps_4.0.3-3woody2\n');
}
if (deb_check(prefix: 'tomcat4', release: '3.0', reference: '4.0.3-3woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tomcat4 is vulnerable in Debian woody.\nUpgrade to tomcat4_4.0.3-3woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
