# This script was automatically generated from the dsa-221
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Earl Hood, author of mhonarc, a mail to HTML converter, discovered a
cross site scripting vulnerability in this package.  A specially
crafted HTML mail message can introduce foreign scripting content in
archives, by-passing MHonArc\'s HTML script filtering.
For the current stable distribution (woody) this problem has been
fixed in version 2.5.2-1.3.
For the old stable distribution (potato) this problem has been fixed
in version 2.4.4-1.3.
For the unstable distribution (sid) this problem has been fixed in
version 2.5.14-1.
We recommend that you upgrade your mhonarc package.


Solution : http://www.debian.org/security/2003/dsa-221
Risk factor : High';

if (description) {
 script_id(15058);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "221");
 script_cve_id("CVE-2002-1388");
 script_bugtraq_id(6479);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA221] DSA-221-1 mhonarc");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-221-1 mhonarc");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mhonarc', release: '2.2', reference: '2.4.4-1.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mhonarc is vulnerable in Debian 2.2.\nUpgrade to mhonarc_2.4.4-1.3\n');
}
if (deb_check(prefix: 'mhonarc', release: '3.0', reference: '2.5.2-1.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mhonarc is vulnerable in Debian 3.0.\nUpgrade to mhonarc_2.5.2-1.3\n');
}
if (deb_check(prefix: 'mhonarc', release: '3.1', reference: '2.5.14-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mhonarc is vulnerable in Debian 3.1.\nUpgrade to mhonarc_2.5.14-1\n');
}
if (deb_check(prefix: 'mhonarc', release: '2.2', reference: '2.4.4-1.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mhonarc is vulnerable in Debian potato.\nUpgrade to mhonarc_2.4.4-1.3\n');
}
if (deb_check(prefix: 'mhonarc', release: '3.0', reference: '2.5.2-1.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mhonarc is vulnerable in Debian woody.\nUpgrade to mhonarc_2.5.2-1.3\n');
}
if (w) { security_hole(port: 0, data: desc); }
