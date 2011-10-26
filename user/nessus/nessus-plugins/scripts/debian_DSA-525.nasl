# This script was automatically generated from the dsa-525
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Georgi Guninski discovered a buffer overflow bug in Apache\'s mod_proxy
module, whereby a remote user could potentially cause arbitrary code
to be executed with the privileges of an Apache httpd child process
(by default, user www-data).  Note that this bug is only exploitable
if the mod_proxy module is in use.
Note that this bug exists in a module in the apache-common package,
shared by apache, apache-ssl and apache-perl, so this update is
sufficient to correct the bug for all three builds of Apache httpd.
However, on systems using apache-ssl or apache-perl, httpd will not
automatically be restarted.
For the current stable distribution (woody), this problem has been
fixed in version 1.3.26-0woody5.
For the unstable distribution (sid), this problem has been fixed in
version 1.3.31-2.
We recommend that you update your apache package.


Solution : http://www.debian.org/security/2004/dsa-525
Risk factor : High';

if (description) {
 script_id(15362);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "525");
 script_cve_id("CVE-2004-0492");
 script_bugtraq_id(10508);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA525] DSA-525-1 apache");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-525-1 apache");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'apache', release: '3.0', reference: '1.3.26-0woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache is vulnerable in Debian 3.0.\nUpgrade to apache_1.3.26-0woody5\n');
}
if (deb_check(prefix: 'apache-common', release: '3.0', reference: '1.3.26-0woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache-common is vulnerable in Debian 3.0.\nUpgrade to apache-common_1.3.26-0woody5\n');
}
if (deb_check(prefix: 'apache-dev', release: '3.0', reference: '1.3.26-0woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache-dev is vulnerable in Debian 3.0.\nUpgrade to apache-dev_1.3.26-0woody5\n');
}
if (deb_check(prefix: 'apache-doc', release: '3.0', reference: '1.3.26-0woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache-doc is vulnerable in Debian 3.0.\nUpgrade to apache-doc_1.3.26-0woody5\n');
}
if (deb_check(prefix: 'apache', release: '3.1', reference: '1.3.31-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache is vulnerable in Debian 3.1.\nUpgrade to apache_1.3.31-2\n');
}
if (deb_check(prefix: 'apache', release: '3.0', reference: '1.3.26-0woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache is vulnerable in Debian woody.\nUpgrade to apache_1.3.26-0woody5\n');
}
if (w) { security_hole(port: 0, data: desc); }
