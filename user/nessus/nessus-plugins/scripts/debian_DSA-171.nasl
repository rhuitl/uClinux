# This script was automatically generated from the dsa-171
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Stefan Esser discovered several buffer overflows and a broken boundary
check within fetchmail.  If fetchmail is running in multidrop mode
these flaws can be used by remote attackers to crash it or to execute
arbitrary code under the user id of the user running fetchmail.
Depending on the configuration this even allows a remote root
compromise.
These problems have been fixed in version 5.9.11-6.1 for both
fetchmail and fetchmail-ssl for the current stable distribution
(woody), in version 5.3.3-4.2 for fetchmail for the old stable
distribution (potato) and in version 6.1.0-1 for both fetchmail and
fetchmail-ssl for the unstable distribution (sid).  There are no
fetchmail-ssl packages for the old stable distribution (potato) and
thus no updates.
We recommend that you upgrade your fetchmail packages immediately.


Solution : http://www.debian.org/security/2002/dsa-171
Risk factor : High';

if (description) {
 script_id(15008);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "171");
 script_cve_id("CVE-2002-1174", "CVE-2002-1175");
 script_bugtraq_id(5825, 5826, 5827);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA171] DSA-171-1 fetchmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-171-1 fetchmail");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'fetchmail', release: '2.2', reference: '5.3.3-4.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fetchmail is vulnerable in Debian 2.2.\nUpgrade to fetchmail_5.3.3-4.2\n');
}
if (deb_check(prefix: 'fetchmailconf', release: '2.2', reference: '5.3.3-4.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fetchmailconf is vulnerable in Debian 2.2.\nUpgrade to fetchmailconf_5.3.3-4.2\n');
}
if (deb_check(prefix: 'fetchmail', release: '3.0', reference: '5.9.11-6.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fetchmail is vulnerable in Debian 3.0.\nUpgrade to fetchmail_5.9.11-6.1\n');
}
if (deb_check(prefix: 'fetchmail-common', release: '3.0', reference: '5.9.11-6.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fetchmail-common is vulnerable in Debian 3.0.\nUpgrade to fetchmail-common_5.9.11-6.1\n');
}
if (deb_check(prefix: 'fetchmail-ssl', release: '3.0', reference: '5.9.11-6.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fetchmail-ssl is vulnerable in Debian 3.0.\nUpgrade to fetchmail-ssl_5.9.11-6.1\n');
}
if (deb_check(prefix: 'fetchmailconf', release: '3.0', reference: '5.9.11-6.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fetchmailconf is vulnerable in Debian 3.0.\nUpgrade to fetchmailconf_5.9.11-6.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
