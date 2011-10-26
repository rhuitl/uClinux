# This script was automatically generated from the dsa-172
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
It has been discovered that tkmail creates temporary files insecurely.
Exploiting this an attacker with local access can easily create and
overwrite files as another user.
This problem has been fixed in version 4.0beta9-8.1 for the current
stable distribution (woody), in version 4.0beta9-4.1 for the old
stable distribution (potato) and in version 4.0beta9-9 for the
unstable distribution (sid).
We recommend that you upgrade your tkmail packages.


Solution : http://www.debian.org/security/2002/dsa-172
Risk factor : High';

if (description) {
 script_id(15009);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "172");
 script_cve_id("CVE-2002-1193");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA172] DSA-172-1 tkmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-172-1 tkmail");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'tkmail', release: '2.2', reference: '4.0beta9-4.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tkmail is vulnerable in Debian 2.2.\nUpgrade to tkmail_4.0beta9-4.1\n');
}
if (deb_check(prefix: 'tkmail', release: '3.0', reference: '4.0beta9-8.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tkmail is vulnerable in Debian 3.0.\nUpgrade to tkmail_4.0beta9-8.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
