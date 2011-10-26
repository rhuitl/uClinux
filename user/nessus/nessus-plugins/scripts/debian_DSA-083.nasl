# This script was automatically generated from the dsa-083
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Using older versions of procmail it was possible to make procmail
crash by sending it signals.  On systems where procmail is installed
setuid this could be exploited to obtain unauthorized privileges.

This problem has been fixed in version 3.20 by the upstream
maintainer, included in Debian unstable, and was ported back to
version 3.15.2 which is available for the stable Debian GNU/Linux
2.2.

We recommend that you upgrade your procmail package immediately.



Solution : http://www.debian.org/security/2001/dsa-083
Risk factor : High';

if (description) {
 script_id(14920);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "083");
 script_cve_id("CVE-2001-0905");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA083] DSA-083-1 procmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-083-1 procmail");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'procmail', release: '2.2', reference: '3.15.2-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package procmail is vulnerable in Debian 2.2.\nUpgrade to procmail_3.15.2-1\n');
}
if (w) { security_hole(port: 0, data: desc); }
