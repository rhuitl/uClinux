# This script was automatically generated from the dsa-1190
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Oliver Karow discovered that the WebDBM frontend of the MaxDB database
performs insufficient sanitising of requests passed to it, which might
lead to the execution of arbitrary code.
For the stable distribution (sarge) this problem has been fixed in
version 7.5.00.24-4.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you upgrade your maxdb-7.5.00 package.


Solution : http://www.debian.org/security/2006/dsa-1190
Risk factor : High';

if (description) {
 script_id(22904);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1190");
 script_cve_id("CVE-2006-4305");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1190] DSA-1190-1 maxdb-7.5.00");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1190-1 maxdb-7.5.00");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libsqldbc7.5.00', release: '3.1', reference: '7.5.00.24-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libsqldbc7.5.00 is vulnerable in Debian 3.1.\nUpgrade to libsqldbc7.5.00_7.5.00.24-4\n');
}
if (deb_check(prefix: 'libsqldbc7.5.00-dev', release: '3.1', reference: '7.5.00.24-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libsqldbc7.5.00-dev is vulnerable in Debian 3.1.\nUpgrade to libsqldbc7.5.00-dev_7.5.00.24-4\n');
}
if (deb_check(prefix: 'libsqlod7.5.00', release: '3.1', reference: '7.5.00.24-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libsqlod7.5.00 is vulnerable in Debian 3.1.\nUpgrade to libsqlod7.5.00_7.5.00.24-4\n');
}
if (deb_check(prefix: 'libsqlod7.5.00-dev', release: '3.1', reference: '7.5.00.24-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libsqlod7.5.00-dev is vulnerable in Debian 3.1.\nUpgrade to libsqlod7.5.00-dev_7.5.00.24-4\n');
}
if (deb_check(prefix: 'maxdb-dbanalyzer', release: '3.1', reference: '7.5.00.24-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package maxdb-dbanalyzer is vulnerable in Debian 3.1.\nUpgrade to maxdb-dbanalyzer_7.5.00.24-4\n');
}
if (deb_check(prefix: 'maxdb-dbmcli', release: '3.1', reference: '7.5.00.24-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package maxdb-dbmcli is vulnerable in Debian 3.1.\nUpgrade to maxdb-dbmcli_7.5.00.24-4\n');
}
if (deb_check(prefix: 'maxdb-loadercli', release: '3.1', reference: '7.5.00.24-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package maxdb-loadercli is vulnerable in Debian 3.1.\nUpgrade to maxdb-loadercli_7.5.00.24-4\n');
}
if (deb_check(prefix: 'maxdb-lserver', release: '3.1', reference: '7.5.00.24-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package maxdb-lserver is vulnerable in Debian 3.1.\nUpgrade to maxdb-lserver_7.5.00.24-4\n');
}
if (deb_check(prefix: 'maxdb-server', release: '3.1', reference: '7.5.00.24-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package maxdb-server is vulnerable in Debian 3.1.\nUpgrade to maxdb-server_7.5.00.24-4\n');
}
if (deb_check(prefix: 'maxdb-server-7.5.00', release: '3.1', reference: '7.5.00.24-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package maxdb-server-7.5.00 is vulnerable in Debian 3.1.\nUpgrade to maxdb-server-7.5.00_7.5.00.24-4\n');
}
if (deb_check(prefix: 'maxdb-server-dbg-7.5.00', release: '3.1', reference: '7.5.00.24-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package maxdb-server-dbg-7.5.00 is vulnerable in Debian 3.1.\nUpgrade to maxdb-server-dbg-7.5.00_7.5.00.24-4\n');
}
if (deb_check(prefix: 'maxdb-sqlcli', release: '3.1', reference: '7.5.00.24-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package maxdb-sqlcli is vulnerable in Debian 3.1.\nUpgrade to maxdb-sqlcli_7.5.00.24-4\n');
}
if (deb_check(prefix: 'maxdb-webtools', release: '3.1', reference: '7.5.00.24-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package maxdb-webtools is vulnerable in Debian 3.1.\nUpgrade to maxdb-webtools_7.5.00.24-4\n');
}
if (deb_check(prefix: 'python-maxdb', release: '3.1', reference: '7.5.00.24-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python-maxdb is vulnerable in Debian 3.1.\nUpgrade to python-maxdb_7.5.00.24-4\n');
}
if (deb_check(prefix: 'python-maxdb-loader', release: '3.1', reference: '7.5.00.24-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python-maxdb-loader is vulnerable in Debian 3.1.\nUpgrade to python-maxdb-loader_7.5.00.24-4\n');
}
if (deb_check(prefix: 'python2.3-maxdb', release: '3.1', reference: '7.5.00.24-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.3-maxdb is vulnerable in Debian 3.1.\nUpgrade to python2.3-maxdb_7.5.00.24-4\n');
}
if (deb_check(prefix: 'python2.3-maxdb-loader', release: '3.1', reference: '7.5.00.24-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.3-maxdb-loader is vulnerable in Debian 3.1.\nUpgrade to python2.3-maxdb-loader_7.5.00.24-4\n');
}
if (deb_check(prefix: 'python2.4-maxdb', release: '3.1', reference: '7.5.00.24-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.4-maxdb is vulnerable in Debian 3.1.\nUpgrade to python2.4-maxdb_7.5.00.24-4\n');
}
if (deb_check(prefix: 'python2.4-maxdb-loader', release: '3.1', reference: '7.5.00.24-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.4-maxdb-loader is vulnerable in Debian 3.1.\nUpgrade to python2.4-maxdb-loader_7.5.00.24-4\n');
}
if (deb_check(prefix: 'maxdb-7.5.00', release: '3.1', reference: '7.5.00.24-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package maxdb-7.5.00 is vulnerable in Debian sarge.\nUpgrade to maxdb-7.5.00_7.5.00.24-4\n');
}
if (w) { security_hole(port: 0, data: desc); }
