# This script was automatically generated from the dsa-1126
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A problem has been discovered in the IAX2 channel driver of Asterisk,
an Open Source Private Branch Exchange and telephony toolkit, which
may allow a remote attacker to cause a crash of the Asterisk server.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 1.0.7.dfsg.1-2sarge3.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you upgrade your asterisk packages.


Solution : http://www.debian.org/security/2006/dsa-1126
Risk factor : High';

if (description) {
 script_id(22668);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1126");
 script_cve_id("CVE-2006-2898");
 script_bugtraq_id(18295);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1126] DSA-1126-1 asterisk");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1126-1 asterisk");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'asterisk', release: '3.1', reference: '1.0.7.dfsg.1-2sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package asterisk is vulnerable in Debian 3.1.\nUpgrade to asterisk_1.0.7.dfsg.1-2sarge3\n');
}
if (deb_check(prefix: 'asterisk-config', release: '3.1', reference: '1.0.7.dfsg.1-2sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package asterisk-config is vulnerable in Debian 3.1.\nUpgrade to asterisk-config_1.0.7.dfsg.1-2sarge3\n');
}
if (deb_check(prefix: 'asterisk-dev', release: '3.1', reference: '1.0.7.dfsg.1-2sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package asterisk-dev is vulnerable in Debian 3.1.\nUpgrade to asterisk-dev_1.0.7.dfsg.1-2sarge3\n');
}
if (deb_check(prefix: 'asterisk-doc', release: '3.1', reference: '1.0.7.dfsg.1-2sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package asterisk-doc is vulnerable in Debian 3.1.\nUpgrade to asterisk-doc_1.0.7.dfsg.1-2sarge3\n');
}
if (deb_check(prefix: 'asterisk-gtk-console', release: '3.1', reference: '1.0.7.dfsg.1-2sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package asterisk-gtk-console is vulnerable in Debian 3.1.\nUpgrade to asterisk-gtk-console_1.0.7.dfsg.1-2sarge3\n');
}
if (deb_check(prefix: 'asterisk-h323', release: '3.1', reference: '1.0.7.dfsg.1-2sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package asterisk-h323 is vulnerable in Debian 3.1.\nUpgrade to asterisk-h323_1.0.7.dfsg.1-2sarge3\n');
}
if (deb_check(prefix: 'asterisk-sounds-main', release: '3.1', reference: '1.0.7.dfsg.1-2sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package asterisk-sounds-main is vulnerable in Debian 3.1.\nUpgrade to asterisk-sounds-main_1.0.7.dfsg.1-2sarge3\n');
}
if (deb_check(prefix: 'asterisk-web-vmail', release: '3.1', reference: '1.0.7.dfsg.1-2sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package asterisk-web-vmail is vulnerable in Debian 3.1.\nUpgrade to asterisk-web-vmail_1.0.7.dfsg.1-2sarge3\n');
}
if (deb_check(prefix: 'asterisk', release: '3.1', reference: '1.0.7.dfsg.1-2sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package asterisk is vulnerable in Debian sarge.\nUpgrade to asterisk_1.0.7.dfsg.1-2sarge3\n');
}
if (w) { security_hole(port: 0, data: desc); }
