# This script was automatically generated from the dsa-205
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Steve Kemp and James Antill found several buffer overflows in the
gtetrinet (a multiplayer tetris-like game) package as shipped in
Debian GNU/Linux 3.0, which could be abused by a malicious server.
This has been fixed in upstream version 0.4.4 and release
0.4.1-9woody1.1 of the Debian package.


Solution : http://www.debian.org/security/2002/dsa-205
Risk factor : High';

if (description) {
 script_id(15042);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "205");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA205] DSA-205-1 gtetrinet");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-205-1 gtetrinet");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gtetrinet', release: '3.0', reference: '0.4.1-9woody1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gtetrinet is vulnerable in Debian 3.0.\nUpgrade to gtetrinet_0.4.1-9woody1.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
