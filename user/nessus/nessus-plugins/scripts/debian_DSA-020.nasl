# This script was automatically generated from the dsa-020
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = 'The Zend people have found a vulnerability in older
versions of PHP4 (the original advisory speaks of 4.0.4 while the bugs are
present in 4.0.3 as well). It is possible to specify PHP directives on a
per-directory basis which leads to a remote attacker crafting an HTTP request
that would cause the next page to be served with the wrong values for these
directives. Also even if PHP is installed, it can be activated and deactivated
on a per-directory or per-virtual host basis using the "engine=on" or
"engine=off" directive. This setting can be leaked to other virtual hosts on
the same machine, effectively disabling PHP for those hosts and resulting in
PHP source code being sent to the client instead of being executed on the
server.


Solution : http://www.debian.org/security/2001/dsa-020
Risk factor : High';

if (description) {
 script_id(14857);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "020");
 script_cve_id("CVE-2001-0108", "CVE-2001-1385");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA020] DSA-020-1 php4");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-020-1 php4");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'php4', release: '2.2', reference: '4.0.3pl1-0potato1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4 is vulnerable in Debian 2.2.\nUpgrade to php4_4.0.3pl1-0potato1.1\n');
}
if (deb_check(prefix: 'php4-cgi', release: '2.2', reference: '4.0.3pl1-0potato1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-cgi is vulnerable in Debian 2.2.\nUpgrade to php4-cgi_4.0.3pl1-0potato1.1\n');
}
if (deb_check(prefix: 'php4-cgi-gd', release: '2.2', reference: '4.0.3pl1-0potato1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-cgi-gd is vulnerable in Debian 2.2.\nUpgrade to php4-cgi-gd_4.0.3pl1-0potato1.1\n');
}
if (deb_check(prefix: 'php4-cgi-imap', release: '2.2', reference: '4.0.3pl1-0potato1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-cgi-imap is vulnerable in Debian 2.2.\nUpgrade to php4-cgi-imap_4.0.3pl1-0potato1.1\n');
}
if (deb_check(prefix: 'php4-cgi-ldap', release: '2.2', reference: '4.0.3pl1-0potato1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-cgi-ldap is vulnerable in Debian 2.2.\nUpgrade to php4-cgi-ldap_4.0.3pl1-0potato1.1\n');
}
if (deb_check(prefix: 'php4-cgi-mhash', release: '2.2', reference: '4.0.3pl1-0potato1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-cgi-mhash is vulnerable in Debian 2.2.\nUpgrade to php4-cgi-mhash_4.0.3pl1-0potato1.1\n');
}
if (deb_check(prefix: 'php4-cgi-mysql', release: '2.2', reference: '4.0.3pl1-0potato1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-cgi-mysql is vulnerable in Debian 2.2.\nUpgrade to php4-cgi-mysql_4.0.3pl1-0potato1.1\n');
}
if (deb_check(prefix: 'php4-cgi-pgsql', release: '2.2', reference: '4.0.3pl1-0potato1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-cgi-pgsql is vulnerable in Debian 2.2.\nUpgrade to php4-cgi-pgsql_4.0.3pl1-0potato1.1\n');
}
if (deb_check(prefix: 'php4-cgi-snmp', release: '2.2', reference: '4.0.3pl1-0potato1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-cgi-snmp is vulnerable in Debian 2.2.\nUpgrade to php4-cgi-snmp_4.0.3pl1-0potato1.1\n');
}
if (deb_check(prefix: 'php4-cgi-xml', release: '2.2', reference: '4.0.3pl1-0potato1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-cgi-xml is vulnerable in Debian 2.2.\nUpgrade to php4-cgi-xml_4.0.3pl1-0potato1.1\n');
}
if (deb_check(prefix: 'php4-gd', release: '2.2', reference: '4.0.3pl1-0potato1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-gd is vulnerable in Debian 2.2.\nUpgrade to php4-gd_4.0.3pl1-0potato1.1\n');
}
if (deb_check(prefix: 'php4-imap', release: '2.2', reference: '4.0.3pl1-0potato1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-imap is vulnerable in Debian 2.2.\nUpgrade to php4-imap_4.0.3pl1-0potato1.1\n');
}
if (deb_check(prefix: 'php4-ldap', release: '2.2', reference: '4.0.3pl1-0potato1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-ldap is vulnerable in Debian 2.2.\nUpgrade to php4-ldap_4.0.3pl1-0potato1.1\n');
}
if (deb_check(prefix: 'php4-mhash', release: '2.2', reference: '4.0.3pl1-0potato1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-mhash is vulnerable in Debian 2.2.\nUpgrade to php4-mhash_4.0.3pl1-0potato1.1\n');
}
if (deb_check(prefix: 'php4-mysql', release: '2.2', reference: '4.0.3pl1-0potato1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-mysql is vulnerable in Debian 2.2.\nUpgrade to php4-mysql_4.0.3pl1-0potato1.1\n');
}
if (deb_check(prefix: 'php4-pgsql', release: '2.2', reference: '4.0.3pl1-0potato1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-pgsql is vulnerable in Debian 2.2.\nUpgrade to php4-pgsql_4.0.3pl1-0potato1.1\n');
}
if (deb_check(prefix: 'php4-snmp', release: '2.2', reference: '4.0.3pl1-0potato1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-snmp is vulnerable in Debian 2.2.\nUpgrade to php4-snmp_4.0.3pl1-0potato1.1\n');
}
if (deb_check(prefix: 'php4-xml', release: '2.2', reference: '4.0.3pl1-0potato1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-xml is vulnerable in Debian 2.2.\nUpgrade to php4-xml_4.0.3pl1-0potato1.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
