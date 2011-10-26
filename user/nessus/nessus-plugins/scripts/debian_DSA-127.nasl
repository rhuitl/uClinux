# This script was automatically generated from the dsa-127
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
An internal audit by the xpilot (a multi-player tactical manoeuvring
game for X) maintainers revealed a buffer overflow in xpilot server.
This overflow can be abused by remote attackers to gain access to
the server under which the xpilot server is running.
This has been fixed in upstream version 4.5.1 and version
4.1.0-4.U.4alpha2.4.potato1 of the Debian package.


Solution : http://www.debian.org/security/2002/dsa-127
Risk factor : High';

if (description) {
 script_id(14964);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "127");
 script_cve_id("CVE-2002-0179");
 script_bugtraq_id(4534);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA127] DSA-127-1 xpilot-server");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-127-1 xpilot-server");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'xpilot', release: '2.2', reference: '4.1.0-4.U.4alpha2.4.potato1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpilot is vulnerable in Debian 2.2.\nUpgrade to xpilot_4.1.0-4.U.4alpha2.4.potato1\n');
}
if (deb_check(prefix: 'xpilot-client-nas', release: '2.2', reference: '4.1.0-4.U.4alpha2.4.potato1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpilot-client-nas is vulnerable in Debian 2.2.\nUpgrade to xpilot-client-nas_4.1.0-4.U.4alpha2.4.potato1\n');
}
if (deb_check(prefix: 'xpilot-client-nosound', release: '2.2', reference: '4.1.0-4.U.4alpha2.4.potato1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpilot-client-nosound is vulnerable in Debian 2.2.\nUpgrade to xpilot-client-nosound_4.1.0-4.U.4alpha2.4.potato1\n');
}
if (deb_check(prefix: 'xpilot-client-rplay', release: '2.2', reference: '4.1.0-4.U.4alpha2.4.potato1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpilot-client-rplay is vulnerable in Debian 2.2.\nUpgrade to xpilot-client-rplay_4.1.0-4.U.4alpha2.4.potato1\n');
}
if (deb_check(prefix: 'xpilot-server', release: '2.2', reference: '4.1.0-4.U.4alpha2.4.potato1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpilot-server is vulnerable in Debian 2.2.\nUpgrade to xpilot-server_4.1.0-4.U.4alpha2.4.potato1\n');
}
if (w) { security_hole(port: 0, data: desc); }
