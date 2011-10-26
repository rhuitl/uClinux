# This script was automatically generated from the dsa-197
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A problem in the Courier sqwebmail package, a CGI program to grant
authenticated access to local mailboxes, has been discovered.  The
program did not drop permissions fast enough upon startup under
certain circumstances so a local shell user can execute the sqwebmail
binary and manage to read an arbitrary file on the local filesystem.
This problem has been fixed in version 0.37.3-2.3 for the current
stable distribution (woody) and in version 0.40.0-1 for the unstable
distribution (sid).  The old stable distribution (potato) does not
contain Courier sqwebmail packages.  courier-ssl packages
are also not affected since they don\'t expose an sqwebmail package.
We recommend that you upgrade your sqwebmail package immediately.


Solution : http://www.debian.org/security/2002/dsa-197
Risk factor : High';

if (description) {
 script_id(15034);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "197");
 script_cve_id("CVE-2002-1311");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA197] DSA-197-1 courier");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-197-1 courier");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'courier-authdaemon', release: '3.0', reference: '0.37.3-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-authdaemon is vulnerable in Debian 3.0.\nUpgrade to courier-authdaemon_0.37.3-2.3\n');
}
if (deb_check(prefix: 'courier-authmysql', release: '3.0', reference: '0.37.3-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-authmysql is vulnerable in Debian 3.0.\nUpgrade to courier-authmysql_0.37.3-2.3\n');
}
if (deb_check(prefix: 'courier-base', release: '3.0', reference: '0.37.3-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-base is vulnerable in Debian 3.0.\nUpgrade to courier-base_0.37.3-2.3\n');
}
if (deb_check(prefix: 'courier-debug', release: '3.0', reference: '0.37.3-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-debug is vulnerable in Debian 3.0.\nUpgrade to courier-debug_0.37.3-2.3\n');
}
if (deb_check(prefix: 'courier-doc', release: '3.0', reference: '0.37.3-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-doc is vulnerable in Debian 3.0.\nUpgrade to courier-doc_0.37.3-2.3\n');
}
if (deb_check(prefix: 'courier-imap', release: '3.0', reference: '1.4.3-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-imap is vulnerable in Debian 3.0.\nUpgrade to courier-imap_1.4.3-2.3\n');
}
if (deb_check(prefix: 'courier-imap-ssl', release: '3.0', reference: '1.4.3-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-imap-ssl is vulnerable in Debian 3.0.\nUpgrade to courier-imap-ssl_1.4.3-3.1\n');
}
if (deb_check(prefix: 'courier-ldap', release: '3.0', reference: '0.37.3-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-ldap is vulnerable in Debian 3.0.\nUpgrade to courier-ldap_0.37.3-2.3\n');
}
if (deb_check(prefix: 'courier-maildrop', release: '3.0', reference: '0.37.3-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-maildrop is vulnerable in Debian 3.0.\nUpgrade to courier-maildrop_0.37.3-2.3\n');
}
if (deb_check(prefix: 'courier-mlm', release: '3.0', reference: '0.37.3-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-mlm is vulnerable in Debian 3.0.\nUpgrade to courier-mlm_0.37.3-2.3\n');
}
if (deb_check(prefix: 'courier-mta', release: '3.0', reference: '0.37.3-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-mta is vulnerable in Debian 3.0.\nUpgrade to courier-mta_0.37.3-2.3\n');
}
if (deb_check(prefix: 'courier-pcp', release: '3.0', reference: '0.37.3-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-pcp is vulnerable in Debian 3.0.\nUpgrade to courier-pcp_0.37.3-2.3\n');
}
if (deb_check(prefix: 'courier-pop', release: '3.0', reference: '0.37.3-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-pop is vulnerable in Debian 3.0.\nUpgrade to courier-pop_0.37.3-2.3\n');
}
if (deb_check(prefix: 'courier-webadmin', release: '3.0', reference: '0.37.3-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-webadmin is vulnerable in Debian 3.0.\nUpgrade to courier-webadmin_0.37.3-2.3\n');
}
if (deb_check(prefix: 'sqwebmail', release: '3.0', reference: '0.37.3-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sqwebmail is vulnerable in Debian 3.0.\nUpgrade to sqwebmail_0.37.3-2.3\n');
}
if (w) { security_hole(port: 0, data: desc); }
