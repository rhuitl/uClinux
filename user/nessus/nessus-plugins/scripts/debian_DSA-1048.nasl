# This script was automatically generated from the dsa-1048
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several problems have been discovered in Asterisk, an Open Source
Private Branch Exchange (telephone control center).  The Common
Vulnerabilities and Exposures project identifies the following
problems:
    Adam Pointon discovered that due to missing input sanitising it is
    possible to retrieve recorded phone messages for a different
    extension.
    Emmanouel Kellinis discovered an integer signedness error that
    could trigger a buffer overflow and hence allow the execution of
    arbitrary code.
For the old stable distribution (woody) this problem has been fixed in
version 0.1.11-3woody1.
For the stable distribution (sarge) this problem has been fixed in
version 1.0.7.dfsg.1-2sarge2.
For the unstable distribution (sid) this problem has been fixed in
version 1.2.7.1.dfsg-1.
We recommend that you upgrade your asterisk package.


Solution : http://www.debian.org/security/2006/dsa-1048
Risk factor : High';

if (description) {
 script_id(22590);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1048");
 script_cve_id("CVE-2005-3559", "CVE-2006-1827");
 script_bugtraq_id(15336);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1048] DSA-1048-1 asterisk");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1048-1 asterisk");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'asterisk', release: '', reference: '1.2.7.1.dfsg-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package asterisk is vulnerable in Debian .\nUpgrade to asterisk_1.2.7.1.dfsg-1\n');
}
if (deb_check(prefix: 'asterisk', release: '3.0', reference: '0.1.11-3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package asterisk is vulnerable in Debian 3.0.\nUpgrade to asterisk_0.1.11-3woody1\n');
}
if (deb_check(prefix: 'asterisk', release: '3.1', reference: '1.0.7.dfsg.1-2sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package asterisk is vulnerable in Debian 3.1.\nUpgrade to asterisk_1.0.7.dfsg.1-2sarge2\n');
}
if (deb_check(prefix: 'asterisk-config', release: '3.1', reference: '1.0.7.dfsg.1-2sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package asterisk-config is vulnerable in Debian 3.1.\nUpgrade to asterisk-config_1.0.7.dfsg.1-2sarge2\n');
}
if (deb_check(prefix: 'asterisk-dev', release: '3.1', reference: '1.0.7.dfsg.1-2sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package asterisk-dev is vulnerable in Debian 3.1.\nUpgrade to asterisk-dev_1.0.7.dfsg.1-2sarge2\n');
}
if (deb_check(prefix: 'asterisk-doc', release: '3.1', reference: '1.0.7.dfsg.1-2sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package asterisk-doc is vulnerable in Debian 3.1.\nUpgrade to asterisk-doc_1.0.7.dfsg.1-2sarge2\n');
}
if (deb_check(prefix: 'asterisk-gtk-console', release: '3.1', reference: '1.0.7.dfsg.1-2sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package asterisk-gtk-console is vulnerable in Debian 3.1.\nUpgrade to asterisk-gtk-console_1.0.7.dfsg.1-2sarge2\n');
}
if (deb_check(prefix: 'asterisk-h323', release: '3.1', reference: '1.0.7.dfsg.1-2sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package asterisk-h323 is vulnerable in Debian 3.1.\nUpgrade to asterisk-h323_1.0.7.dfsg.1-2sarge2\n');
}
if (deb_check(prefix: 'asterisk-sounds-main', release: '3.1', reference: '1.0.7.dfsg.1-2sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package asterisk-sounds-main is vulnerable in Debian 3.1.\nUpgrade to asterisk-sounds-main_1.0.7.dfsg.1-2sarge2\n');
}
if (deb_check(prefix: 'asterisk-web-vmail', release: '3.1', reference: '1.0.7.dfsg.1-2sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package asterisk-web-vmail is vulnerable in Debian 3.1.\nUpgrade to asterisk-web-vmail_1.0.7.dfsg.1-2sarge2\n');
}
if (deb_check(prefix: 'asterisk', release: '3.1', reference: '1.0.7.dfsg.1-2sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package asterisk is vulnerable in Debian sarge.\nUpgrade to asterisk_1.0.7.dfsg.1-2sarge2\n');
}
if (deb_check(prefix: 'asterisk', release: '3.0', reference: '0.1.11-3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package asterisk is vulnerable in Debian woody.\nUpgrade to asterisk_0.1.11-3woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
