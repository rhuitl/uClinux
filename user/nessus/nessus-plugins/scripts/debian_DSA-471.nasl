# This script was automatically generated from the dsa-471
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A vulnerability was discovered recently in Interchange, an e-commerce
and general HTTP database display system.  This vulnerability can be
exploited by an attacker to expose the content of arbitrary variables.
An attacker may learn SQL access information for your Interchange
application and use this information to read and manipulate sensitive
data.
For the stable distribution (woody) this problem has been fixed in
version 4.8.3.20020306-1.woody.2.
For the unstable distribution (sid) this problem has been fixed in
version 5.0.1-1.
We recommend that you upgrade your interchange package.


Solution : http://www.debian.org/security/2004/dsa-471
Risk factor : High';

if (description) {
 script_id(15308);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "471");
 script_cve_id("CVE-2004-0374");
 script_bugtraq_id(10005);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA471] DSA-471-1 interchange");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-471-1 interchange");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'interchange', release: '3.0', reference: '4.8.3.20020306-1.woody.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package interchange is vulnerable in Debian 3.0.\nUpgrade to interchange_4.8.3.20020306-1.woody.2\n');
}
if (deb_check(prefix: 'interchange-cat-foundation', release: '3.0', reference: '4.8.3.20020306-1.woody.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package interchange-cat-foundation is vulnerable in Debian 3.0.\nUpgrade to interchange-cat-foundation_4.8.3.20020306-1.woody.2\n');
}
if (deb_check(prefix: 'interchange-ui', release: '3.0', reference: '4.8.3.20020306-1.woody.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package interchange-ui is vulnerable in Debian 3.0.\nUpgrade to interchange-ui_4.8.3.20020306-1.woody.2\n');
}
if (deb_check(prefix: 'libapache-mod-interchange', release: '3.0', reference: '4.8.3.20020306-1.woody.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapache-mod-interchange is vulnerable in Debian 3.0.\nUpgrade to libapache-mod-interchange_4.8.3.20020306-1.woody.2\n');
}
if (deb_check(prefix: 'interchange', release: '3.1', reference: '5.0.1-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package interchange is vulnerable in Debian 3.1.\nUpgrade to interchange_5.0.1-1\n');
}
if (deb_check(prefix: 'interchange', release: '3.0', reference: '4.8.3.20020306-1.woody.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package interchange is vulnerable in Debian woody.\nUpgrade to interchange_4.8.3.20020306-1.woody.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
