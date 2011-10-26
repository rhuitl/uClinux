# This script was automatically generated from the dsa-533
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A cross-site scripting vulnerability was discovered in sqwebmail, a
web mail application provided by the courier mail suite, whereby an
attacker could cause web script to be executed within the security
context of the sqwebmail application by injecting it via an email
message.
For the current stable distribution (woody), this problem has been
fixed in version 0.37.3-2.5.
For the unstable distribution (sid), this problem has been fixed in
version 0.45.4-4.
We recommend that you update your courier package.


Solution : http://www.debian.org/security/2004/dsa-533
Risk factor : High';

if (description) {
 script_id(15370);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "533");
 script_cve_id("CVE-2004-0591");
 script_bugtraq_id(10588);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA533] DSA-533-1 courier");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-533-1 courier");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'courier-authdaemon', release: '3.0', reference: '0.37.3-2.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-authdaemon is vulnerable in Debian 3.0.\nUpgrade to courier-authdaemon_0.37.3-2.5\n');
}
if (deb_check(prefix: 'courier-authmysql', release: '3.0', reference: '0.37.3-2.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-authmysql is vulnerable in Debian 3.0.\nUpgrade to courier-authmysql_0.37.3-2.5\n');
}
if (deb_check(prefix: 'courier-base', release: '3.0', reference: '0.37.3-2.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-base is vulnerable in Debian 3.0.\nUpgrade to courier-base_0.37.3-2.5\n');
}
if (deb_check(prefix: 'courier-debug', release: '3.0', reference: '0.37.3-2.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-debug is vulnerable in Debian 3.0.\nUpgrade to courier-debug_0.37.3-2.5\n');
}
if (deb_check(prefix: 'courier-doc', release: '3.0', reference: '0.37.3-2.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-doc is vulnerable in Debian 3.0.\nUpgrade to courier-doc_0.37.3-2.5\n');
}
if (deb_check(prefix: 'courier-imap', release: '3.0', reference: '1.4.3-2.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-imap is vulnerable in Debian 3.0.\nUpgrade to courier-imap_1.4.3-2.5\n');
}
if (deb_check(prefix: 'courier-ldap', release: '3.0', reference: '0.37.3-2.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-ldap is vulnerable in Debian 3.0.\nUpgrade to courier-ldap_0.37.3-2.5\n');
}
if (deb_check(prefix: 'courier-maildrop', release: '3.0', reference: '0.37.3-2.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-maildrop is vulnerable in Debian 3.0.\nUpgrade to courier-maildrop_0.37.3-2.5\n');
}
if (deb_check(prefix: 'courier-mlm', release: '3.0', reference: '0.37.3-2.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-mlm is vulnerable in Debian 3.0.\nUpgrade to courier-mlm_0.37.3-2.5\n');
}
if (deb_check(prefix: 'courier-mta', release: '3.0', reference: '0.37.3-2.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-mta is vulnerable in Debian 3.0.\nUpgrade to courier-mta_0.37.3-2.5\n');
}
if (deb_check(prefix: 'courier-pcp', release: '3.0', reference: '0.37.3-2.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-pcp is vulnerable in Debian 3.0.\nUpgrade to courier-pcp_0.37.3-2.5\n');
}
if (deb_check(prefix: 'courier-pop', release: '3.0', reference: '0.37.3-2.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-pop is vulnerable in Debian 3.0.\nUpgrade to courier-pop_0.37.3-2.5\n');
}
if (deb_check(prefix: 'courier-webadmin', release: '3.0', reference: '0.37.3-2.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-webadmin is vulnerable in Debian 3.0.\nUpgrade to courier-webadmin_0.37.3-2.5\n');
}
if (deb_check(prefix: 'sqwebmail', release: '3.0', reference: '0.37.3-2.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sqwebmail is vulnerable in Debian 3.0.\nUpgrade to sqwebmail_0.37.3-2.5\n');
}
if (deb_check(prefix: 'courier', release: '3.1', reference: '0.45.4-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier is vulnerable in Debian 3.1.\nUpgrade to courier_0.45.4-4\n');
}
if (deb_check(prefix: 'courier', release: '3.0', reference: '0.37.3-2.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier is vulnerable in Debian woody.\nUpgrade to courier_0.37.3-2.5\n');
}
if (w) { security_hole(port: 0, data: desc); }
