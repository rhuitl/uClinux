# This script was automatically generated from the dsa-090
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The xtel (an X emulator for minitel) package as distributed with Debian
GNU/Linux 2.2 has two possible symlink attacks:
Both problems have been fixed in version 3.2.1-4.potato.1 .



Solution : http://www.debian.org/security/2001/dsa-090
Risk factor : High';

if (description) {
 script_id(14927);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "090");
 script_cve_id("CVE-2002-0334");
 script_bugtraq_id(3626);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA090] DSA-090-1 xtel");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-090-1 xtel");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'xtel', release: '2.2', reference: '3.2.1-4.potato.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xtel is vulnerable in Debian 2.2.\nUpgrade to xtel_3.2.1-4.potato.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
