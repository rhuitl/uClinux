# This script was automatically generated from the dsa-833
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
This update only covers binary packages for the big endian MIPS
architecture that was mysteriously forgotten in the earlier update.
For completeness below is the original advisory text:
A stack-based buffer overflow in the init_syms function of MySQL, a
popular database, has been discovered that allows remote authenticated
users who can create user-defined functions to execute arbitrary code
via a long function_name field.  The ability to create user-defined
functions is not typically granted to untrusted users.
The following vulnerability matrix explains which version of MySQL in
which distribution has this problem fixed:
We recommend that you upgrade your mysql-dfsg-4.1 packages.


Solution : http://www.debian.org/security/2005/dsa-833
Risk factor : High';

if (description) {
 script_id(19802);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "833");
 script_cve_id("CVE-2005-2558");
 script_bugtraq_id(14509);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA833] DSA-833-2 mysql-dfsg-4.1");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-833-2 mysql-dfsg-4.1");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libmysqlclient14', release: '3.1', reference: '4.1.11a-4sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmysqlclient14 is vulnerable in Debian 3.1.\nUpgrade to libmysqlclient14_4.1.11a-4sarge2\n');
}
if (deb_check(prefix: 'libmysqlclient14-dev', release: '3.1', reference: '4.1.11a-4sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmysqlclient14-dev is vulnerable in Debian 3.1.\nUpgrade to libmysqlclient14-dev_4.1.11a-4sarge2\n');
}
if (deb_check(prefix: 'mysql-client-4.1', release: '3.1', reference: '4.1.11a-4sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-client-4.1 is vulnerable in Debian 3.1.\nUpgrade to mysql-client-4.1_4.1.11a-4sarge2\n');
}
if (deb_check(prefix: 'mysql-common-4.1', release: '3.1', reference: '4.1.11a-4sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-common-4.1 is vulnerable in Debian 3.1.\nUpgrade to mysql-common-4.1_4.1.11a-4sarge2\n');
}
if (deb_check(prefix: 'mysql-server-4.1', release: '3.1', reference: '4.1.11a-4sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-server-4.1 is vulnerable in Debian 3.1.\nUpgrade to mysql-server-4.1_4.1.11a-4sarge2\n');
}
if (w) { security_hole(port: 0, data: desc); }
