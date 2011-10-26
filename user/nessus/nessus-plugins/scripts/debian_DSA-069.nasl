# This script was automatically generated from the dsa-069
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The version of xloadimage (a graphics files viewer for X) that was
shipped in Debian GNU/Linux 2.2 has a buffer overflow in the code that
handles FACES format images. This could be exploited by an attacker by
tricking someone into viewing a specially crafted image using xloadimage
which would allow them to execute arbitrary code.

This problem was fixed in version 4.1-5potato1.



Solution : http://www.debian.org/security/2001/dsa-069
Risk factor : High';

if (description) {
 script_id(14906);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "069");
 script_cve_id("CVE-2001-0775");
 script_bugtraq_id(3006);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA069] DSA-069-1 xloadimage");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-069-1 xloadimage");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'xloadimage', release: '2.2', reference: '4.1-5potato1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xloadimage is vulnerable in Debian 2.2.\nUpgrade to xloadimage_4.1-5potato1\n');
}
if (w) { security_hole(port: 0, data: desc); }
