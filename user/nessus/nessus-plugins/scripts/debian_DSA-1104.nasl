# This script was automatically generated from the dsa-1104
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Loading malformed XML documents can cause buffer overflows in
OpenOffice.org, a free office suite, and cause a denial of service or
execute arbitrary code.  It turned out that the correction in DSA
1104-1 was not sufficient, hence, another update. For completeness
please find the original advisory text below:
Several vulnerabilities have been discovered in OpenOffice.org, a free
office suite.  The Common Vulnerabilities and Exposures Project
identifies the following problems:
    It turned out to be possible to embed arbitrary BASIC macros in
    documents in a way that OpenOffice.org does not see them but
    executes them anyway without any user interaction.
    It is possible to evade the Java sandbox with specially crafted
    Java applets.
    Loading malformed XML documents can cause buffer overflows and
    cause a denial of service or execute arbitrary code.
This update has the Mozilla component disabled, so that the
Mozilla/LDAP addressbook feature won\'t work anymore.  It didn\'t work on
anything else than i386 on sarge either.
The old stable distribution (woody) does not contain OpenOffice.org
packages.
For the stable distribution (sarge) this problem has been fixed in
version 1.1.3-9sarge3.
For the unstable distribution (sid) this problem has been fixed in
version 2.0.3-1.
We recommend that you upgrade your OpenOffice.org packages.


Solution : http://www.debian.org/security/2006/dsa-1104
Risk factor : High';

if (description) {
 script_id(22646);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1104");
 script_cve_id("CVE-2006-2198", "CVE-2006-2199", "CVE-2006-3117");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1104] DSA-1104-2 openoffice.org");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1104-2 openoffice.org");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'openoffice.org', release: '', reference: '2.0.3-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org is vulnerable in Debian .\nUpgrade to openoffice.org_2.0.3-1\n');
}
if (deb_check(prefix: 'openoffice.org', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org is vulnerable in Debian 3.1.\nUpgrade to openoffice.org_1.1.3-9sarge3\n');
}
if (deb_check(prefix: 'openoffice.org-bin', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org-bin is vulnerable in Debian 3.1.\nUpgrade to openoffice.org-bin_1.1.3-9sarge3\n');
}
if (deb_check(prefix: 'openoffice.org-dev', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org-dev is vulnerable in Debian 3.1.\nUpgrade to openoffice.org-dev_1.1.3-9sarge3\n');
}
if (deb_check(prefix: 'openoffice.org-evolution', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org-evolution is vulnerable in Debian 3.1.\nUpgrade to openoffice.org-evolution_1.1.3-9sarge3\n');
}
if (deb_check(prefix: 'openoffice.org-gtk-gnome', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org-gtk-gnome is vulnerable in Debian 3.1.\nUpgrade to openoffice.org-gtk-gnome_1.1.3-9sarge3\n');
}
if (deb_check(prefix: 'openoffice.org-kde', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org-kde is vulnerable in Debian 3.1.\nUpgrade to openoffice.org-kde_1.1.3-9sarge3\n');
}
if (deb_check(prefix: 'openoffice.org-l10n-af', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org-l10n-af is vulnerable in Debian 3.1.\nUpgrade to openoffice.org-l10n-af_1.1.3-9sarge3\n');
}
if (deb_check(prefix: 'openoffice.org-l10n-ar', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org-l10n-ar is vulnerable in Debian 3.1.\nUpgrade to openoffice.org-l10n-ar_1.1.3-9sarge3\n');
}
if (deb_check(prefix: 'openoffice.org-l10n-ca', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org-l10n-ca is vulnerable in Debian 3.1.\nUpgrade to openoffice.org-l10n-ca_1.1.3-9sarge3\n');
}
if (deb_check(prefix: 'openoffice.org-l10n-cs', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org-l10n-cs is vulnerable in Debian 3.1.\nUpgrade to openoffice.org-l10n-cs_1.1.3-9sarge3\n');
}
if (deb_check(prefix: 'openoffice.org-l10n-cy', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org-l10n-cy is vulnerable in Debian 3.1.\nUpgrade to openoffice.org-l10n-cy_1.1.3-9sarge3\n');
}
if (deb_check(prefix: 'openoffice.org-l10n-da', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org-l10n-da is vulnerable in Debian 3.1.\nUpgrade to openoffice.org-l10n-da_1.1.3-9sarge3\n');
}
if (deb_check(prefix: 'openoffice.org-l10n-de', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org-l10n-de is vulnerable in Debian 3.1.\nUpgrade to openoffice.org-l10n-de_1.1.3-9sarge3\n');
}
if (deb_check(prefix: 'openoffice.org-l10n-el', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org-l10n-el is vulnerable in Debian 3.1.\nUpgrade to openoffice.org-l10n-el_1.1.3-9sarge3\n');
}
if (deb_check(prefix: 'openoffice.org-l10n-en', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org-l10n-en is vulnerable in Debian 3.1.\nUpgrade to openoffice.org-l10n-en_1.1.3-9sarge3\n');
}
if (deb_check(prefix: 'openoffice.org-l10n-es', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org-l10n-es is vulnerable in Debian 3.1.\nUpgrade to openoffice.org-l10n-es_1.1.3-9sarge3\n');
}
if (deb_check(prefix: 'openoffice.org-l10n-et', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org-l10n-et is vulnerable in Debian 3.1.\nUpgrade to openoffice.org-l10n-et_1.1.3-9sarge3\n');
}
if (deb_check(prefix: 'openoffice.org-l10n-eu', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org-l10n-eu is vulnerable in Debian 3.1.\nUpgrade to openoffice.org-l10n-eu_1.1.3-9sarge3\n');
}
if (deb_check(prefix: 'openoffice.org-l10n-fi', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org-l10n-fi is vulnerable in Debian 3.1.\nUpgrade to openoffice.org-l10n-fi_1.1.3-9sarge3\n');
}
if (deb_check(prefix: 'openoffice.org-l10n-fr', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org-l10n-fr is vulnerable in Debian 3.1.\nUpgrade to openoffice.org-l10n-fr_1.1.3-9sarge3\n');
}
if (deb_check(prefix: 'openoffice.org-l10n-gl', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org-l10n-gl is vulnerable in Debian 3.1.\nUpgrade to openoffice.org-l10n-gl_1.1.3-9sarge3\n');
}
if (deb_check(prefix: 'openoffice.org-l10n-he', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org-l10n-he is vulnerable in Debian 3.1.\nUpgrade to openoffice.org-l10n-he_1.1.3-9sarge3\n');
}
if (deb_check(prefix: 'openoffice.org-l10n-hi', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org-l10n-hi is vulnerable in Debian 3.1.\nUpgrade to openoffice.org-l10n-hi_1.1.3-9sarge3\n');
}
if (deb_check(prefix: 'openoffice.org-l10n-hu', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org-l10n-hu is vulnerable in Debian 3.1.\nUpgrade to openoffice.org-l10n-hu_1.1.3-9sarge3\n');
}
if (deb_check(prefix: 'openoffice.org-l10n-it', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org-l10n-it is vulnerable in Debian 3.1.\nUpgrade to openoffice.org-l10n-it_1.1.3-9sarge3\n');
}
if (deb_check(prefix: 'openoffice.org-l10n-ja', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org-l10n-ja is vulnerable in Debian 3.1.\nUpgrade to openoffice.org-l10n-ja_1.1.3-9sarge3\n');
}
if (deb_check(prefix: 'openoffice.org-l10n-kn', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org-l10n-kn is vulnerable in Debian 3.1.\nUpgrade to openoffice.org-l10n-kn_1.1.3-9sarge3\n');
}
if (deb_check(prefix: 'openoffice.org-l10n-ko', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org-l10n-ko is vulnerable in Debian 3.1.\nUpgrade to openoffice.org-l10n-ko_1.1.3-9sarge3\n');
}
if (deb_check(prefix: 'openoffice.org-l10n-lt', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org-l10n-lt is vulnerable in Debian 3.1.\nUpgrade to openoffice.org-l10n-lt_1.1.3-9sarge3\n');
}
if (deb_check(prefix: 'openoffice.org-l10n-nb', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org-l10n-nb is vulnerable in Debian 3.1.\nUpgrade to openoffice.org-l10n-nb_1.1.3-9sarge3\n');
}
if (deb_check(prefix: 'openoffice.org-l10n-nl', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org-l10n-nl is vulnerable in Debian 3.1.\nUpgrade to openoffice.org-l10n-nl_1.1.3-9sarge3\n');
}
if (deb_check(prefix: 'openoffice.org-l10n-nn', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org-l10n-nn is vulnerable in Debian 3.1.\nUpgrade to openoffice.org-l10n-nn_1.1.3-9sarge3\n');
}
if (deb_check(prefix: 'openoffice.org-l10n-ns', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org-l10n-ns is vulnerable in Debian 3.1.\nUpgrade to openoffice.org-l10n-ns_1.1.3-9sarge3\n');
}
if (deb_check(prefix: 'openoffice.org-l10n-pl', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org-l10n-pl is vulnerable in Debian 3.1.\nUpgrade to openoffice.org-l10n-pl_1.1.3-9sarge3\n');
}
if (deb_check(prefix: 'openoffice.org-l10n-pt', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org-l10n-pt is vulnerable in Debian 3.1.\nUpgrade to openoffice.org-l10n-pt_1.1.3-9sarge3\n');
}
if (deb_check(prefix: 'openoffice.org-l10n-pt-br', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org-l10n-pt-br is vulnerable in Debian 3.1.\nUpgrade to openoffice.org-l10n-pt-br_1.1.3-9sarge3\n');
}
if (deb_check(prefix: 'openoffice.org-l10n-ru', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org-l10n-ru is vulnerable in Debian 3.1.\nUpgrade to openoffice.org-l10n-ru_1.1.3-9sarge3\n');
}
if (deb_check(prefix: 'openoffice.org-l10n-sk', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org-l10n-sk is vulnerable in Debian 3.1.\nUpgrade to openoffice.org-l10n-sk_1.1.3-9sarge3\n');
}
if (deb_check(prefix: 'openoffice.org-l10n-sl', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org-l10n-sl is vulnerable in Debian 3.1.\nUpgrade to openoffice.org-l10n-sl_1.1.3-9sarge3\n');
}
if (deb_check(prefix: 'openoffice.org-l10n-sv', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org-l10n-sv is vulnerable in Debian 3.1.\nUpgrade to openoffice.org-l10n-sv_1.1.3-9sarge3\n');
}
if (deb_check(prefix: 'openoffice.org-l10n-th', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org-l10n-th is vulnerable in Debian 3.1.\nUpgrade to openoffice.org-l10n-th_1.1.3-9sarge3\n');
}
if (deb_check(prefix: 'openoffice.org-l10n-tn', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org-l10n-tn is vulnerable in Debian 3.1.\nUpgrade to openoffice.org-l10n-tn_1.1.3-9sarge3\n');
}
if (deb_check(prefix: 'openoffice.org-l10n-tr', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org-l10n-tr is vulnerable in Debian 3.1.\nUpgrade to openoffice.org-l10n-tr_1.1.3-9sarge3\n');
}
if (deb_check(prefix: 'openoffice.org-l10n-zh-cn', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org-l10n-zh-cn is vulnerable in Debian 3.1.\nUpgrade to openoffice.org-l10n-zh-cn_1.1.3-9sarge3\n');
}
if (deb_check(prefix: 'openoffice.org-l10n-zh-tw', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org-l10n-zh-tw is vulnerable in Debian 3.1.\nUpgrade to openoffice.org-l10n-zh-tw_1.1.3-9sarge3\n');
}
if (deb_check(prefix: 'openoffice.org-l10n-zu', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org-l10n-zu is vulnerable in Debian 3.1.\nUpgrade to openoffice.org-l10n-zu_1.1.3-9sarge3\n');
}
if (deb_check(prefix: 'openoffice.org-mimelnk', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org-mimelnk is vulnerable in Debian 3.1.\nUpgrade to openoffice.org-mimelnk_1.1.3-9sarge3\n');
}
if (deb_check(prefix: 'openoffice.org-thesaurus-en-us', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org-thesaurus-en-us is vulnerable in Debian 3.1.\nUpgrade to openoffice.org-thesaurus-en-us_1.1.3-9sarge3\n');
}
if (deb_check(prefix: 'ttf-opensymbol', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ttf-opensymbol is vulnerable in Debian 3.1.\nUpgrade to ttf-opensymbol_1.1.3-9sarge3\n');
}
if (deb_check(prefix: 'openoffice.org', release: '3.1', reference: '1.1.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openoffice.org is vulnerable in Debian sarge.\nUpgrade to openoffice.org_1.1.3-9sarge3\n');
}
if (w) { security_hole(port: 0, data: desc); }
