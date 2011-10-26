# This script was automatically generated from the dsa-732
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
"infamous41md" discovered several vulnerabilities in the GNU mailutils
package which contains utilities for handling mail.  These problems
can lead to a denial of service or the execution of arbitrary code.
The Common Vulnerabilities and Exposures project identifies the
following vulnerabilities.
    Buffer overflow mail header handling may allow a remote attacker
    to execute commands with the privileges of the targeted user.
    Combined integer and heap overflow in the fetch routine can lead
    to the execution of arbitrary code.
    Denial of service in the fetch routine.
    Format string vulnerability can lead to the execution of arbitrary
    code.
For the stable distribution (woody) these problems have been fixed in
version 20020409-1woody2.
For the testing distribution (sarge) these problems have been fixed in
version 0.6.1-4.
For the unstable distribution (sid) these problems have been fixed in
version 0.6.1-4.
We recommend that you upgrade your mailutils packages.


Solution : http://www.debian.org/security/2005/dsa-732
Risk factor : High';

if (description) {
 script_id(18519);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "732");
 script_cve_id("CVE-2005-1520", "CVE-2005-1521", "CVE-2005-1522", "CVE-2005-1523");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA732] DSA-732-1 mailutils");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-732-1 mailutils");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libmailutils0', release: '3.0', reference: '20020409-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmailutils0 is vulnerable in Debian 3.0.\nUpgrade to libmailutils0_20020409-1woody2\n');
}
if (deb_check(prefix: 'libmailutils0-dev', release: '3.0', reference: '20020409-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmailutils0-dev is vulnerable in Debian 3.0.\nUpgrade to libmailutils0-dev_20020409-1woody2\n');
}
if (deb_check(prefix: 'mailutils', release: '3.0', reference: '20020409-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mailutils is vulnerable in Debian 3.0.\nUpgrade to mailutils_20020409-1woody2\n');
}
if (deb_check(prefix: 'mailutils-doc', release: '3.0', reference: '20020409-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mailutils-doc is vulnerable in Debian 3.0.\nUpgrade to mailutils-doc_20020409-1woody2\n');
}
if (deb_check(prefix: 'mailutils-imap4d', release: '3.0', reference: '20020409-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mailutils-imap4d is vulnerable in Debian 3.0.\nUpgrade to mailutils-imap4d_20020409-1woody2\n');
}
if (deb_check(prefix: 'mailutils-pop3d', release: '3.0', reference: '20020409-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mailutils-pop3d is vulnerable in Debian 3.0.\nUpgrade to mailutils-pop3d_20020409-1woody2\n');
}
if (deb_check(prefix: 'mailutils', release: '3.1', reference: '0.6.1-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mailutils is vulnerable in Debian 3.1.\nUpgrade to mailutils_0.6.1-4\n');
}
if (deb_check(prefix: 'mailutils', release: '3.1', reference: '0.6.1-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mailutils is vulnerable in Debian sarge.\nUpgrade to mailutils_0.6.1-4\n');
}
if (deb_check(prefix: 'mailutils', release: '3.0', reference: '20020409-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mailutils is vulnerable in Debian woody.\nUpgrade to mailutils_20020409-1woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
