# This script was automatically generated from the dsa-829
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A stack-based buffer overflow in the init_syms function of MySQL, a
popular database, has been discovered that allows remote authenticated
users who can create user-defined functions to execute arbitrary code
via a long function_name field.  The ability to create user-defined
functions is not typically granted to untrusted users.
The following vulnerability matrix shows which version of MySQL in
which distribution has this problem fixed:
We recommend that you upgrade your mysql packages.


Solution : http://www.debian.org/security/2005/dsa-829
Risk factor : High';

if (description) {
 script_id(19798);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "829");
 script_cve_id("CVE-2005-2558");
 script_bugtraq_id(14509);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA829] DSA-829-1 mysql");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-829-1 mysql");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libmysqlclient10', release: '3.0', reference: '3.23.49-8.14')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmysqlclient10 is vulnerable in Debian 3.0.\nUpgrade to libmysqlclient10_3.23.49-8.14\n');
}
if (deb_check(prefix: 'libmysqlclient10-dev', release: '3.0', reference: '3.23.49-8.14')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmysqlclient10-dev is vulnerable in Debian 3.0.\nUpgrade to libmysqlclient10-dev_3.23.49-8.14\n');
}
if (deb_check(prefix: 'mysql-client', release: '3.0', reference: '3.23.49-8.14')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-client is vulnerable in Debian 3.0.\nUpgrade to mysql-client_3.23.49-8.14\n');
}
if (deb_check(prefix: 'mysql-common', release: '3.0', reference: '3.23.49-8.14')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-common is vulnerable in Debian 3.0.\nUpgrade to mysql-common_3.23.49-8.14\n');
}
if (deb_check(prefix: 'mysql-doc', release: '3.0', reference: '3.23.49-8.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-doc is vulnerable in Debian 3.0.\nUpgrade to mysql-doc_3.23.49-8.5\n');
}
if (deb_check(prefix: 'mysql-server', release: '3.0', reference: '3.23.49-8.14')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-server is vulnerable in Debian 3.0.\nUpgrade to mysql-server_3.23.49-8.14\n');
}
if (w) { security_hole(port: 0, data: desc); }
