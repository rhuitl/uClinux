# This script was automatically generated from the dsa-908
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Colin Leroy discovered several buffer overflows in a number of
importer routines in sylpheed-claws, an extended version of the
Sylpheed mail client, that could lead to the execution of arbitrary
code.
The following matrix explains which versions fix this vulnerability
We recommend that you upgrade your sylpheed-claws package.


Solution : http://www.debian.org/security/2005/dsa-908
Risk factor : High';

if (description) {
 script_id(22774);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "908");
 script_cve_id("CVE-2005-3354");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA908] DSA-908-1 sylpheed-claws");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-908-1 sylpheed-claws");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'sylpheed-claws', release: '3.0', reference: '0.7.4claws-3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sylpheed-claws is vulnerable in Debian 3.0.\nUpgrade to sylpheed-claws_0.7.4claws-3woody1\n');
}
if (deb_check(prefix: 'libsylpheed-claws-dev', release: '3.1', reference: '1.0.4-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libsylpheed-claws-dev is vulnerable in Debian 3.1.\nUpgrade to libsylpheed-claws-dev_1.0.4-1sarge1\n');
}
if (deb_check(prefix: 'sylpheed-claws', release: '3.1', reference: '1.0.4-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sylpheed-claws is vulnerable in Debian 3.1.\nUpgrade to sylpheed-claws_1.0.4-1sarge1\n');
}
if (deb_check(prefix: 'sylpheed-claws-clamav', release: '3.1', reference: '1.0.4-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sylpheed-claws-clamav is vulnerable in Debian 3.1.\nUpgrade to sylpheed-claws-clamav_1.0.4-1sarge1\n');
}
if (deb_check(prefix: 'sylpheed-claws-dillo-viewer', release: '3.1', reference: '1.0.4-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sylpheed-claws-dillo-viewer is vulnerable in Debian 3.1.\nUpgrade to sylpheed-claws-dillo-viewer_1.0.4-1sarge1\n');
}
if (deb_check(prefix: 'sylpheed-claws-i18n', release: '3.1', reference: '1.0.4-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sylpheed-claws-i18n is vulnerable in Debian 3.1.\nUpgrade to sylpheed-claws-i18n_1.0.4-1sarge1\n');
}
if (deb_check(prefix: 'sylpheed-claws-image-viewer', release: '3.1', reference: '1.0.4-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sylpheed-claws-image-viewer is vulnerable in Debian 3.1.\nUpgrade to sylpheed-claws-image-viewer_1.0.4-1sarge1\n');
}
if (deb_check(prefix: 'sylpheed-claws-pgpmime', release: '3.1', reference: '1.0.4-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sylpheed-claws-pgpmime is vulnerable in Debian 3.1.\nUpgrade to sylpheed-claws-pgpmime_1.0.4-1sarge1\n');
}
if (deb_check(prefix: 'sylpheed-claws-plugins', release: '3.1', reference: '1.0.4-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sylpheed-claws-plugins is vulnerable in Debian 3.1.\nUpgrade to sylpheed-claws-plugins_1.0.4-1sarge1\n');
}
if (deb_check(prefix: 'sylpheed-claws-scripts', release: '3.1', reference: '1.0.4-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sylpheed-claws-scripts is vulnerable in Debian 3.1.\nUpgrade to sylpheed-claws-scripts_1.0.4-1sarge1\n');
}
if (deb_check(prefix: 'sylpheed-claws-spamassassin', release: '3.1', reference: '1.0.4-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sylpheed-claws-spamassassin is vulnerable in Debian 3.1.\nUpgrade to sylpheed-claws-spamassassin_1.0.4-1sarge1\n');
}
if (deb_check(prefix: 'sylpheed-claws-trayicon', release: '3.1', reference: '1.0.4-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sylpheed-claws-trayicon is vulnerable in Debian 3.1.\nUpgrade to sylpheed-claws-trayicon_1.0.4-1sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
