# This script was automatically generated from the dsa-784
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A problem has been discovered in the Courier Mail Server.  DNS
failures were not handled properly when looking up Sender Policy
Framework (SPF) records, which could allow attackers to cause memory
corruption.  The default configuration on Debian has SPF checking
disabled, so most machines are not vulnerable.  This is explained in
the "courier" manpage, section SENDER POLICY FRAMEWORK KEYWORDS.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 0.47-4sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 0.47-6.
We recommend that you upgrade your courier-mta package.


Solution : http://www.debian.org/security/2005/dsa-784
Risk factor : High';

if (description) {
 script_id(19527);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "784");
 script_cve_id("CVE-2005-2151");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA784] DSA-784-1 courier");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-784-1 courier");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'courier', release: '', reference: '0.47-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier is vulnerable in Debian .\nUpgrade to courier_0.47-6\n');
}
if (deb_check(prefix: 'courier-authdaemon', release: '3.1', reference: '0.47-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-authdaemon is vulnerable in Debian 3.1.\nUpgrade to courier-authdaemon_0.47-4sarge1\n');
}
if (deb_check(prefix: 'courier-authmysql', release: '3.1', reference: '0.47-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-authmysql is vulnerable in Debian 3.1.\nUpgrade to courier-authmysql_0.47-4sarge1\n');
}
if (deb_check(prefix: 'courier-authpostgresql', release: '3.1', reference: '0.47-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-authpostgresql is vulnerable in Debian 3.1.\nUpgrade to courier-authpostgresql_0.47-4sarge1\n');
}
if (deb_check(prefix: 'courier-base', release: '3.1', reference: '0.47-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-base is vulnerable in Debian 3.1.\nUpgrade to courier-base_0.47-4sarge1\n');
}
if (deb_check(prefix: 'courier-doc', release: '3.1', reference: '0.47-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-doc is vulnerable in Debian 3.1.\nUpgrade to courier-doc_0.47-4sarge1\n');
}
if (deb_check(prefix: 'courier-faxmail', release: '3.1', reference: '0.47-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-faxmail is vulnerable in Debian 3.1.\nUpgrade to courier-faxmail_0.47-4sarge1\n');
}
if (deb_check(prefix: 'courier-imap', release: '3.1', reference: '3.0.8-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-imap is vulnerable in Debian 3.1.\nUpgrade to courier-imap_3.0.8-4sarge1\n');
}
if (deb_check(prefix: 'courier-imap-ssl', release: '3.1', reference: '3.0.8-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-imap-ssl is vulnerable in Debian 3.1.\nUpgrade to courier-imap-ssl_3.0.8-4sarge1\n');
}
if (deb_check(prefix: 'courier-ldap', release: '3.1', reference: '0.47-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-ldap is vulnerable in Debian 3.1.\nUpgrade to courier-ldap_0.47-4sarge1\n');
}
if (deb_check(prefix: 'courier-maildrop', release: '3.1', reference: '0.47-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-maildrop is vulnerable in Debian 3.1.\nUpgrade to courier-maildrop_0.47-4sarge1\n');
}
if (deb_check(prefix: 'courier-mlm', release: '3.1', reference: '0.47-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-mlm is vulnerable in Debian 3.1.\nUpgrade to courier-mlm_0.47-4sarge1\n');
}
if (deb_check(prefix: 'courier-mta', release: '3.1', reference: '0.47-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-mta is vulnerable in Debian 3.1.\nUpgrade to courier-mta_0.47-4sarge1\n');
}
if (deb_check(prefix: 'courier-mta-ssl', release: '3.1', reference: '0.47-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-mta-ssl is vulnerable in Debian 3.1.\nUpgrade to courier-mta-ssl_0.47-4sarge1\n');
}
if (deb_check(prefix: 'courier-pcp', release: '3.1', reference: '0.47-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-pcp is vulnerable in Debian 3.1.\nUpgrade to courier-pcp_0.47-4sarge1\n');
}
if (deb_check(prefix: 'courier-pop', release: '3.1', reference: '0.47-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-pop is vulnerable in Debian 3.1.\nUpgrade to courier-pop_0.47-4sarge1\n');
}
if (deb_check(prefix: 'courier-pop-ssl', release: '3.1', reference: '0.47-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-pop-ssl is vulnerable in Debian 3.1.\nUpgrade to courier-pop-ssl_0.47-4sarge1\n');
}
if (deb_check(prefix: 'courier-ssl', release: '3.1', reference: '0.47-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-ssl is vulnerable in Debian 3.1.\nUpgrade to courier-ssl_0.47-4sarge1\n');
}
if (deb_check(prefix: 'courier-webadmin', release: '3.1', reference: '0.47-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-webadmin is vulnerable in Debian 3.1.\nUpgrade to courier-webadmin_0.47-4sarge1\n');
}
if (deb_check(prefix: 'sqwebmail', release: '3.1', reference: '0.47-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sqwebmail is vulnerable in Debian 3.1.\nUpgrade to sqwebmail_0.47-4sarge1\n');
}
if (deb_check(prefix: 'courier', release: '3.1', reference: '0.47-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier is vulnerable in Debian sarge.\nUpgrade to courier_0.47-4sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
