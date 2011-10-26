# This script was automatically generated from the dsa-013
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = 'Nicolas Gregoire has reported a buffer overflow in the
mysql server that leads to a remote exploit. An attacker could gain mysqld
privileges (and thus gaining access to all the databases). 

We recommend you upgrade your mysql package immediately.


Solution : http://www.debian.org/security/2001/dsa-013
Risk factor : High';

if (description) {
 script_id(14850);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "013");
 script_cve_id("CVE-2001-1274");
 script_bugtraq_id(2262);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA013] DSA-013 MySQL");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-013 MySQL");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mysql-client', release: '2.2', reference: '3.22.32-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-client is vulnerable in Debian 2.2.\nUpgrade to mysql-client_3.22.32-4\n');
}
if (deb_check(prefix: 'mysql-doc', release: '2.2', reference: '3.22.32-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-doc is vulnerable in Debian 2.2.\nUpgrade to mysql-doc_3.22.32-4\n');
}
if (deb_check(prefix: 'mysql-server', release: '2.2', reference: '3.22.32-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-server is vulnerable in Debian 2.2.\nUpgrade to mysql-server_3.22.32-4\n');
}
if (w) { security_hole(port: 0, data: desc); }
