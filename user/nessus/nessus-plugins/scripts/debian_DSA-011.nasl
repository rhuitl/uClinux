# This script was automatically generated from the dsa-011
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = ' Immunix reports that mgetty does not create temporary
files in a secure manner, which could lead to a symlink attack. This has been
corrected in mgetty 1.1.21-3potato1

We recommend you upgrade your mgetty package immediately.


Solution : http://www.debian.org/security/2001/dsa-011
Risk factor : High';

if (description) {
 script_id(14848);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "011");
 script_cve_id("CVE-2001-0141");
 script_bugtraq_id(2187);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA011] DSA-011-2 mgetty");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-011-2 mgetty");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mgetty', release: '2.2', reference: '1.1.21-3potato1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mgetty is vulnerable in Debian 2.2.\nUpgrade to mgetty_1.1.21-3potato1\n');
}
if (deb_check(prefix: 'mgetty-docs', release: '2.2', reference: '1.1.21-3potato1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mgetty-docs is vulnerable in Debian 2.2.\nUpgrade to mgetty-docs_1.1.21-3potato1\n');
}
if (deb_check(prefix: 'mgetty-fax', release: '2.2', reference: '1.1.21-3potato1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mgetty-fax is vulnerable in Debian 2.2.\nUpgrade to mgetty-fax_1.1.21-3potato1\n');
}
if (deb_check(prefix: 'mgetty-viewfax', release: '2.2', reference: '1.1.21-3potato1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mgetty-viewfax is vulnerable in Debian 2.2.\nUpgrade to mgetty-viewfax_1.1.21-3potato1\n');
}
if (deb_check(prefix: 'mgetty-voice', release: '2.2', reference: '1.1.21-3potato1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mgetty-voice is vulnerable in Debian 2.2.\nUpgrade to mgetty-voice_1.1.21-3potato1\n');
}
if (w) { security_hole(port: 0, data: desc); }
