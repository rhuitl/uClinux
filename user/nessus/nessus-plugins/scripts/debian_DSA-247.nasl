# This script was automatically generated from the dsa-247
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The developers of courier, an integrated user side mail server,
discovered a problem in the PostgreSQL auth module.  Not all
potentially malicious characters were sanitized before the username
was passed to the PostgreSQL engine.  An attacker could inject
arbitrary SQL commands and queries exploiting this vulnerability.  The
MySQL auth module is not affected.
For the stable distribution (woody) this problem has been fixed in
version 0.37.3-3.3.
The old stable distribution (potato) does not contain courier packages.
For the unstable distribution (sid) this problem has been fixed in
version 0.40.2-3.
We recommend that you upgrade your courier-authpostgresql package.


Solution : http://www.debian.org/security/2003/dsa-247
Risk factor : High';

if (description) {
 script_id(15084);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "247");
 script_cve_id("CVE-2003-0040");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA247] DSA-247-1 courier-ssl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-247-1 courier-ssl");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'courier-authpostgresql', release: '3.0', reference: '0.37.3-3.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-authpostgresql is vulnerable in Debian 3.0.\nUpgrade to courier-authpostgresql_0.37.3-3.3\n');
}
if (deb_check(prefix: 'courier-imap-ssl', release: '3.0', reference: '1.4.3-3.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-imap-ssl is vulnerable in Debian 3.0.\nUpgrade to courier-imap-ssl_1.4.3-3.3\n');
}
if (deb_check(prefix: 'courier-mta-ssl', release: '3.0', reference: '0.37.3-3.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-mta-ssl is vulnerable in Debian 3.0.\nUpgrade to courier-mta-ssl_0.37.3-3.3\n');
}
if (deb_check(prefix: 'courier-pop-ssl', release: '3.0', reference: '0.37.3-3.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-pop-ssl is vulnerable in Debian 3.0.\nUpgrade to courier-pop-ssl_0.37.3-3.3\n');
}
if (deb_check(prefix: 'courier-ssl', release: '3.0', reference: '0.37.3-3.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier-ssl is vulnerable in Debian 3.0.\nUpgrade to courier-ssl_0.37.3-3.3\n');
}
if (deb_check(prefix: 'courier', release: '3.1', reference: '0.40.2-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier is vulnerable in Debian 3.1.\nUpgrade to courier_0.40.2-3\n');
}
if (deb_check(prefix: 'courier', release: '3.0', reference: '0.37.3-3.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package courier is vulnerable in Debian woody.\nUpgrade to courier_0.37.3-3.3\n');
}
if (w) { security_hole(port: 0, data: desc); }
