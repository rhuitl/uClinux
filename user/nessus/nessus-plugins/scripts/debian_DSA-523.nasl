# This script was automatically generated from the dsa-523
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Ulf Härnhammar discovered a buffer overflow vulnerability in www-sql,
a CGI program which enables the creation of dynamic web pages by
embedding SQL statements in HTML.  By exploiting this
vulnerability, a local user could cause the execution of arbitrary
code by creating a web page and processing it with www-sql.
For the current stable distribution (woody), this problem has been
fixed in version 0.5.7-17woody1.
For the unstable distribution (sid), this problem will be fixed soon.
We recommend that you update your www-sql package.


Solution : http://www.debian.org/security/2004/dsa-523
Risk factor : High';

if (description) {
 script_id(15360);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "523");
 script_cve_id("CVE-2004-0455");
 script_bugtraq_id(10577);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA523] DSA-523-1 www-sql");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-523-1 www-sql");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'www-mysql', release: '3.0', reference: '0.5.7-17woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package www-mysql is vulnerable in Debian 3.0.\nUpgrade to www-mysql_0.5.7-17woody1\n');
}
if (deb_check(prefix: 'www-pgsql', release: '3.0', reference: '0.5.7-17woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package www-pgsql is vulnerable in Debian 3.0.\nUpgrade to www-pgsql_0.5.7-17woody1\n');
}
if (deb_check(prefix: 'www-sql', release: '3.0', reference: '0.5.7-17woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package www-sql is vulnerable in Debian woody.\nUpgrade to www-sql_0.5.7-17woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
