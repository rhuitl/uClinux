# This script was automatically generated from the dsa-395
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Aldrin Martoq has discovered a denial of service (DoS) vulnerability in
Apache Tomcat 4.0.x. Sending several non-HTTP requests to Tomcat\'s HTTP
connector makes Tomcat reject further requests on this port until it is
restarted.
For the current stable distribution (woody) this problem has been fixed
in version 4.0.3-3woody3.
For the unstable distribution (sid) this problem does not exist in the
current version 4.1.24-2.
We recommend that you upgrade your tomcat4 packages and restart the
tomcat server.


Solution : http://www.debian.org/security/2003/dsa-395
Risk factor : High';

if (description) {
 script_id(15232);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "395");
 script_cve_id("CVE-2003-0866");
 script_bugtraq_id(8824);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA395] DSA-395-1 tomcat4");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-395-1 tomcat4");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libtomcat4-java', release: '3.0', reference: '4.0.3-3woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtomcat4-java is vulnerable in Debian 3.0.\nUpgrade to libtomcat4-java_4.0.3-3woody3\n');
}
if (deb_check(prefix: 'tomcat4', release: '3.0', reference: '4.0.3-3woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tomcat4 is vulnerable in Debian 3.0.\nUpgrade to tomcat4_4.0.3-3woody3\n');
}
if (deb_check(prefix: 'tomcat4-webapps', release: '3.0', reference: '4.0.3-3woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tomcat4-webapps is vulnerable in Debian 3.0.\nUpgrade to tomcat4-webapps_4.0.3-3woody3\n');
}
if (deb_check(prefix: 'tomcat4', release: '3.0', reference: '4.0.3-3woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tomcat4 is vulnerable in Debian woody.\nUpgrade to tomcat4_4.0.3-3woody3\n');
}
if (w) { security_hole(port: 0, data: desc); }
