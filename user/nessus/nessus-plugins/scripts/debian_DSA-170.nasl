# This script was automatically generated from the dsa-170
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A security vulnerability has been found in all Tomcat 4.x releases.
This problem allows an attacker to use a specially crafted URL to
return the unprocessed source code of a JSP page, or, under special
circumstances, a static resource which would otherwise have been
protected by security constraints, without the need for being properly
authenticated.
This problem has been fixed in version 4.0.3-3woody1 for the current
stable distribution (woody) and in version 4.1.12-1 for the unstable
release (sid).  The old stable release (potato) does not contain
tomcat packages.  Also, packages for tomcat3 are not vulnerable to
this problem.
We recommend that you upgrade your tomcat package immediately.


Solution : http://www.debian.org/security/2002/dsa-170
Risk factor : High';

if (description) {
 script_id(15007);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "170");
 script_cve_id("CVE-2002-1148");
 script_bugtraq_id(5786);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA170] DSA-170-1 tomcat4");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-170-1 tomcat4");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libtomcat4-java', release: '3.0', reference: '4.0.3-3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtomcat4-java is vulnerable in Debian 3.0.\nUpgrade to libtomcat4-java_4.0.3-3woody1\n');
}
if (deb_check(prefix: 'tomcat4', release: '3.0', reference: '4.0.3-3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tomcat4 is vulnerable in Debian 3.0.\nUpgrade to tomcat4_4.0.3-3woody1\n');
}
if (deb_check(prefix: 'tomcat4-webapps', release: '3.0', reference: '4.0.3-3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tomcat4-webapps is vulnerable in Debian 3.0.\nUpgrade to tomcat4-webapps_4.0.3-3woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
