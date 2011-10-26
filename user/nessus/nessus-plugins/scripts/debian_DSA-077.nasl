# This script was automatically generated from the dsa-077
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Vladimir Ivaschenko found a problem in squid (a popular proxy cache).
He discovered that there was a flaw in the code to handle FTP PUT
commands: when a mkdir-only request was done squid would detect
an internal error and exit. Since squid is configured to restart
itself on problems this is not a big problem.

This has been fixed in version 2.2.5-3.2. This problem is logged
as bug 233 in the squid bugtracker and will also be fixed in
future squid releases.



Solution : http://www.debian.org/security/2001/dsa-077
Risk factor : High';

if (description) {
 script_id(14914);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "077");
 script_cve_id("CVE-2001-0843");
 script_bugtraq_id(3354);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA077] DSA-077-1 squid");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-077-1 squid");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'squid', release: '2.2', reference: '2.2.5-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squid is vulnerable in Debian 2.2.\nUpgrade to squid_2.2.5-3.2\n');
}
if (deb_check(prefix: 'squid-cgi', release: '2.2', reference: '2.2.5-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squid-cgi is vulnerable in Debian 2.2.\nUpgrade to squid-cgi_2.2.5-3.2\n');
}
if (deb_check(prefix: 'squidclient', release: '2.2', reference: '2.2.5-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squidclient is vulnerable in Debian 2.2.\nUpgrade to squidclient_2.2.5-3.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
