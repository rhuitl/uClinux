# This script was automatically generated from the dsa-129
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
We have received reports that in.uucpd, an authentication agent in the
uucp package, does not properly terminate certain long input strings.
This has been corrected in uucp package version 1.06.1-11potato3 for
Debian 2.2 (potato) and in version 1.06.1-18 for the upcoming (woody)
release.
We recommend you upgrade your uucp package immediately.


Solution : http://www.debian.org/security/2002/dsa-129
Risk factor : High';

if (description) {
 script_id(14966);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "129");
 script_cve_id("CVE-2002-0912");
 script_bugtraq_id(4910);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA129] DSA-129-1 uucp");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-129-1 uucp");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'uucp', release: '2.2', reference: '1.06.1-11potato3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package uucp is vulnerable in Debian 2.2.\nUpgrade to uucp_1.06.1-11potato3\n');
}
if (w) { security_hole(port: 0, data: desc); }
