# This script was automatically generated from the dsa-370
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Florian Zumbiehl reported a vulnerability in pam-pgsql whereby the
username to be used for authentication is used as a format string when
writing a log message.  This vulnerability may allow an attacker to
execute arbitrary code with the privileges of the program requesting
PAM authentication.
For the stable distribution (woody) this problem has been fixed in
version 0.5.2-3woody1.
For the unstable distribution (sid) this problem has been fixed in
version 0.5.2-7.
We recommend that you update your pam-pgsql package.


Solution : http://www.debian.org/security/2003/dsa-370
Risk factor : High';

if (description) {
 script_id(15207);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "370");
 script_cve_id("CVE-2003-0672");
 script_bugtraq_id(8379);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA370] DSA-370-1 pam-pgsql");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-370-1 pam-pgsql");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libpam-pgsql', release: '3.0', reference: '0.5.2-3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpam-pgsql is vulnerable in Debian 3.0.\nUpgrade to libpam-pgsql_0.5.2-3woody1\n');
}
if (deb_check(prefix: 'pam-pgsql', release: '3.1', reference: '0.5.2-7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pam-pgsql is vulnerable in Debian 3.1.\nUpgrade to pam-pgsql_0.5.2-7\n');
}
if (deb_check(prefix: 'pam-pgsql', release: '3.0', reference: '0.5.2-3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pam-pgsql is vulnerable in Debian woody.\nUpgrade to pam-pgsql_0.5.2-3woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
