# This script was automatically generated from the dsa-906
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Colin Leroy discovered several buffer overflows in a number of
importer routines in sylpheed, a light-weight e-mail client with GTK+,
that could lead to the execution of arbitrary code.
The following matrix explains which versions fix this vulnerability
We recommend that you upgrade your sylpheed package.


Solution : http://www.debian.org/security/2005/dsa-906
Risk factor : High';

if (description) {
 script_id(22772);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "906");
 script_cve_id("CVE-2005-3354");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA906] DSA-906-1 sylpheed");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-906-1 sylpheed");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'sylpheed', release: '3.0', reference: '0.7.4-4woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sylpheed is vulnerable in Debian 3.0.\nUpgrade to sylpheed_0.7.4-4woody1\n');
}
if (deb_check(prefix: 'sylpheed-doc', release: '3.0', reference: '0.7.4-4woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sylpheed-doc is vulnerable in Debian 3.0.\nUpgrade to sylpheed-doc_0.7.4-4woody1\n');
}
if (deb_check(prefix: 'sylpheed', release: '3.1', reference: '1.0.4-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sylpheed is vulnerable in Debian 3.1.\nUpgrade to sylpheed_1.0.4-1sarge1\n');
}
if (deb_check(prefix: 'sylpheed-i18n', release: '3.1', reference: '1.0.4-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sylpheed-i18n is vulnerable in Debian 3.1.\nUpgrade to sylpheed-i18n_1.0.4-1sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
