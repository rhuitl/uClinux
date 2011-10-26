# This script was automatically generated from the dsa-071
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Salvatore Sanfilippo found two remotely exploitable problems in
fetchmail while doing a security audit. In both the IMAP code
and the POP3 code, the input isn\'t verified even though it\'s used to store
a number in an array. Since
no bounds checking is done this can be used by an attacker to write
arbitrary data in memory. An attacker can use this if they can get a user
to transfer mail from a custom IMAP or POP3 server they control.

This has been fixed in version 5.3.3-3, we recommend that you
update your fetchmail packages immediately.



Solution : http://www.debian.org/security/2001/dsa-071
Risk factor : High';

if (description) {
 script_id(14908);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "071");
 script_cve_id("CVE-2001-1009");
 script_bugtraq_id(3164, 3166);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA071] DSA-071-1 fetchmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-071-1 fetchmail");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'fetchmail', release: '2.2', reference: '5.3.3-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fetchmail is vulnerable in Debian 2.2.\nUpgrade to fetchmail_5.3.3-3\n');
}
if (deb_check(prefix: 'fetchmailconf', release: '2.2', reference: '5.3.3-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fetchmailconf is vulnerable in Debian 2.2.\nUpgrade to fetchmailconf_5.3.3-3\n');
}
if (w) { security_hole(port: 0, data: desc); }
