# This script was automatically generated from the dsa-148
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A set of problems have been discovered in Hylafax, a flexible
client/server fax software distributed with many GNU/Linux
distributions.  Quoting SecurityFocus the problems are in detail:
These problems have been fixed in version 4.0.2-14.3 for the old
stable distribution (potato), in version 4.1.1-1.1 for the current
stable distribution (woody) and in version 4.1.2-2.1 for the unstable
distribution (sid).
We recommend that you upgrade your hylafax packages.


Solution : http://www.debian.org/security/2002/dsa-148
Risk factor : High';

if (description) {
 script_id(14985);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "148");
 script_cve_id("CVE-2001-1034", "CVE-2002-1049", "CVE-2002-1050");
 script_bugtraq_id(3357, 5348, 5349);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA148] DSA-148-1 hylafax");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-148-1 hylafax");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'hylafax-client', release: '2.2', reference: '4.0.2-14.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hylafax-client is vulnerable in Debian 2.2.\nUpgrade to hylafax-client_4.0.2-14.3\n');
}
if (deb_check(prefix: 'hylafax-doc', release: '2.2', reference: '4.0.2-14.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hylafax-doc is vulnerable in Debian 2.2.\nUpgrade to hylafax-doc_4.0.2-14.3\n');
}
if (deb_check(prefix: 'hylafax-server', release: '2.2', reference: '4.0.2-14.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hylafax-server is vulnerable in Debian 2.2.\nUpgrade to hylafax-server_4.0.2-14.3\n');
}
if (deb_check(prefix: 'hylafax-client', release: '3.0', reference: '4.1.1-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hylafax-client is vulnerable in Debian 3.0.\nUpgrade to hylafax-client_4.1.1-1.1\n');
}
if (deb_check(prefix: 'hylafax-doc', release: '3.0', reference: '4.1.1-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hylafax-doc is vulnerable in Debian 3.0.\nUpgrade to hylafax-doc_4.1.1-1.1\n');
}
if (deb_check(prefix: 'hylafax-server', release: '3.0', reference: '4.1.1-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hylafax-server is vulnerable in Debian 3.0.\nUpgrade to hylafax-server_4.1.1-1.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
