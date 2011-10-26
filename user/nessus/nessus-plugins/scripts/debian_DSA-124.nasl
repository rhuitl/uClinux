# This script was automatically generated from the dsa-124
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The authors of mtr released a new upstream version, noting a
non-exploitable buffer overflow in their ChangeLog.  Przemyslaw
Frasunek, however, found an easy way to exploit this bug, which allows
an attacker to gain access to the raw socket, which makes IP spoofing
and other malicious network activity possible.
The problem has been fixed by the Debian maintainer in version 0.41-6
for the stable distribution of Debian by backporting the upstream fix
and in version 0.48-1 for the testing/unstable distribution.
We recommend that you upgrade your mtr package immediately.


Solution : http://www.debian.org/security/2002/dsa-124
Risk factor : High';

if (description) {
 script_id(14961);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "124");
 script_cve_id("CVE-2002-0497");
 script_bugtraq_id(4217);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA124] DSA-124-1 mtr");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-124-1 mtr");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mtr', release: '2.2', reference: '0.41-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mtr is vulnerable in Debian 2.2.\nUpgrade to mtr_0.41-6\n');
}
if (w) { security_hole(port: 0, data: desc); }
