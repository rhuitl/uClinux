# This script was automatically generated from the dsa-1094
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Joxean Koret discovered several cross-site scripting vulnerabilities in
Gforge, an online collaboration suite for software development, which
allow injection of web script code.
The old stable distribution (woody) does not contain gforge packages.
For the stable distribution (sarge) this problem has been fixed in
version 3.1-31sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 3.1-31sarge1.
We recommend that you upgrade your gforge package.


Solution : http://www.debian.org/security/2006/dsa-1094
Risk factor : High';

if (description) {
 script_id(22636);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1094");
 script_cve_id("CVE-2005-2430");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1094] DSA-1094-1 gforge");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1094-1 gforge");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gforge', release: '', reference: '3.1-31sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gforge is vulnerable in Debian .\nUpgrade to gforge_3.1-31sarge1\n');
}
if (deb_check(prefix: 'gforge', release: '3.1', reference: '3.1-31sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gforge is vulnerable in Debian 3.1.\nUpgrade to gforge_3.1-31sarge1\n');
}
if (deb_check(prefix: 'gforge-common', release: '3.1', reference: '3.1-31sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gforge-common is vulnerable in Debian 3.1.\nUpgrade to gforge-common_3.1-31sarge1\n');
}
if (deb_check(prefix: 'gforge-cvs', release: '3.1', reference: '3.1-31sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gforge-cvs is vulnerable in Debian 3.1.\nUpgrade to gforge-cvs_3.1-31sarge1\n');
}
if (deb_check(prefix: 'gforge-db-postgresql', release: '3.1', reference: '3.1-31sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gforge-db-postgresql is vulnerable in Debian 3.1.\nUpgrade to gforge-db-postgresql_3.1-31sarge1\n');
}
if (deb_check(prefix: 'gforge-dns-bind9', release: '3.1', reference: '3.1-31sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gforge-dns-bind9 is vulnerable in Debian 3.1.\nUpgrade to gforge-dns-bind9_3.1-31sarge1\n');
}
if (deb_check(prefix: 'gforge-ftp-proftpd', release: '3.1', reference: '3.1-31sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gforge-ftp-proftpd is vulnerable in Debian 3.1.\nUpgrade to gforge-ftp-proftpd_3.1-31sarge1\n');
}
if (deb_check(prefix: 'gforge-ldap-openldap', release: '3.1', reference: '3.1-31sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gforge-ldap-openldap is vulnerable in Debian 3.1.\nUpgrade to gforge-ldap-openldap_3.1-31sarge1\n');
}
if (deb_check(prefix: 'gforge-lists-mailman', release: '3.1', reference: '3.1-31sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gforge-lists-mailman is vulnerable in Debian 3.1.\nUpgrade to gforge-lists-mailman_3.1-31sarge1\n');
}
if (deb_check(prefix: 'gforge-mta-exim', release: '3.1', reference: '3.1-31sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gforge-mta-exim is vulnerable in Debian 3.1.\nUpgrade to gforge-mta-exim_3.1-31sarge1\n');
}
if (deb_check(prefix: 'gforge-mta-exim4', release: '3.1', reference: '3.1-31sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gforge-mta-exim4 is vulnerable in Debian 3.1.\nUpgrade to gforge-mta-exim4_3.1-31sarge1\n');
}
if (deb_check(prefix: 'gforge-mta-postfix', release: '3.1', reference: '3.1-31sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gforge-mta-postfix is vulnerable in Debian 3.1.\nUpgrade to gforge-mta-postfix_3.1-31sarge1\n');
}
if (deb_check(prefix: 'gforge-shell-ldap', release: '3.1', reference: '3.1-31sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gforge-shell-ldap is vulnerable in Debian 3.1.\nUpgrade to gforge-shell-ldap_3.1-31sarge1\n');
}
if (deb_check(prefix: 'gforge-sourceforge-transition', release: '3.1', reference: '3.1-31sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gforge-sourceforge-transition is vulnerable in Debian 3.1.\nUpgrade to gforge-sourceforge-transition_3.1-31sarge1\n');
}
if (deb_check(prefix: 'gforge-web-apache', release: '3.1', reference: '3.1-31sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gforge-web-apache is vulnerable in Debian 3.1.\nUpgrade to gforge-web-apache_3.1-31sarge1\n');
}
if (deb_check(prefix: 'sourceforge', release: '3.1', reference: '3.1-31sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sourceforge is vulnerable in Debian 3.1.\nUpgrade to sourceforge_3.1-31sarge1\n');
}
if (deb_check(prefix: 'gforge', release: '3.1', reference: '3.1-31sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gforge is vulnerable in Debian sarge.\nUpgrade to gforge_3.1-31sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
