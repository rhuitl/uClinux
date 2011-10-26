# This script was automatically generated from the dsa-831
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
We recommend that you upgrade your mysql-dfsg packages.


Solution : http://www.debian.org/security/2005/dsa-831
Risk factor : High';

if (description) {
 script_id(19800);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "831");
 script_cve_id("CVE-2005-2558");
 script_bugtraq_id(14509);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA831] DSA-831-1 mysql-dfsg");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-831-1 mysql-dfsg");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libmysqlclient12', release: '3.1', reference: '4.0.24-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmysqlclient12 is vulnerable in Debian 3.1.\nUpgrade to libmysqlclient12_4.0.24-10sarge1\n');
}
if (deb_check(prefix: 'libmysqlclient12-dev', release: '3.1', reference: '4.0.24-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmysqlclient12-dev is vulnerable in Debian 3.1.\nUpgrade to libmysqlclient12-dev_4.0.24-10sarge1\n');
}
if (deb_check(prefix: 'mysql-client', release: '3.1', reference: '4.0.24-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-client is vulnerable in Debian 3.1.\nUpgrade to mysql-client_4.0.24-10sarge1\n');
}
if (deb_check(prefix: 'mysql-common', release: '3.1', reference: '4.0.24-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-common is vulnerable in Debian 3.1.\nUpgrade to mysql-common_4.0.24-10sarge1\n');
}
if (deb_check(prefix: 'mysql-server', release: '3.1', reference: '4.0.24-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-server is vulnerable in Debian 3.1.\nUpgrade to mysql-server_4.0.24-10sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
