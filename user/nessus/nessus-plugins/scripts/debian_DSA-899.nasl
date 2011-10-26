# This script was automatically generated from the dsa-899
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several vulnerabilities have been discovered in egroupware, a
web-based groupware suite.  The Common Vulnerabilities and Exposures
project identifies the following problems:
    Maksymilian Arciemowicz discovered several cross site scripting
    problems in phpsysinfo, which are also present in the imported
    version in egroupware and of which not all were fixed in DSA 724.
    Alexander Heidenreich discovered a cross-site scripting problem in
    the tree view of FUD Forum Bulletin Board Software, which is also
    present in egroupware and allows remote attackers to read private
    posts via a modified mid parameter.
    Christopher Kunz discovered that local variables get overwritten
    unconditionally in phpsyinfo, which are also present in
    egroupware, and are trusted later, which could lead to the
    inclusion of arbitrary files.
    Christopher Kunz discovered that user-supplied input is used
    unsanitised in phpsyinfo and imported in egroupware, causing a
    HTTP Response splitting problem.
The old stable distribution (woody) does not contain egroupware packages.
For the stable distribution (sarge) this problem has been fixed in
version 1.0.0.007-2.dfsg-2sarge4.
For the unstable distribution (sid) this problem has been fixed in
version 1.0.0.009.dfsg-3-3.
We recommend that you upgrade your egroupware packages.


Solution : http://www.debian.org/security/2005/dsa-899
Risk factor : High';

if (description) {
 script_id(22765);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "899");
 script_cve_id("CVE-2005-0870", "CVE-2005-2600", "CVE-2005-3347", "CVE-2005-3348");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA899] DSA-899-1 egroupware");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-899-1 egroupware");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'egroupware', release: '', reference: '1.0.0.009.dfsg-3-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package egroupware is vulnerable in Debian .\nUpgrade to egroupware_1.0.0.009.dfsg-3-3\n');
}
if (deb_check(prefix: 'egroupware', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package egroupware is vulnerable in Debian 3.1.\nUpgrade to egroupware_1.0.0.007-2.dfsg-2sarge4\n');
}
if (deb_check(prefix: 'egroupware-addressbook', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package egroupware-addressbook is vulnerable in Debian 3.1.\nUpgrade to egroupware-addressbook_1.0.0.007-2.dfsg-2sarge4\n');
}
if (deb_check(prefix: 'egroupware-bookmarks', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package egroupware-bookmarks is vulnerable in Debian 3.1.\nUpgrade to egroupware-bookmarks_1.0.0.007-2.dfsg-2sarge4\n');
}
if (deb_check(prefix: 'egroupware-calendar', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package egroupware-calendar is vulnerable in Debian 3.1.\nUpgrade to egroupware-calendar_1.0.0.007-2.dfsg-2sarge4\n');
}
if (deb_check(prefix: 'egroupware-comic', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package egroupware-comic is vulnerable in Debian 3.1.\nUpgrade to egroupware-comic_1.0.0.007-2.dfsg-2sarge4\n');
}
if (deb_check(prefix: 'egroupware-core', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package egroupware-core is vulnerable in Debian 3.1.\nUpgrade to egroupware-core_1.0.0.007-2.dfsg-2sarge4\n');
}
if (deb_check(prefix: 'egroupware-developer-tools', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package egroupware-developer-tools is vulnerable in Debian 3.1.\nUpgrade to egroupware-developer-tools_1.0.0.007-2.dfsg-2sarge4\n');
}
if (deb_check(prefix: 'egroupware-email', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package egroupware-email is vulnerable in Debian 3.1.\nUpgrade to egroupware-email_1.0.0.007-2.dfsg-2sarge4\n');
}
if (deb_check(prefix: 'egroupware-emailadmin', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package egroupware-emailadmin is vulnerable in Debian 3.1.\nUpgrade to egroupware-emailadmin_1.0.0.007-2.dfsg-2sarge4\n');
}
if (deb_check(prefix: 'egroupware-etemplate', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package egroupware-etemplate is vulnerable in Debian 3.1.\nUpgrade to egroupware-etemplate_1.0.0.007-2.dfsg-2sarge4\n');
}
if (deb_check(prefix: 'egroupware-felamimail', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package egroupware-felamimail is vulnerable in Debian 3.1.\nUpgrade to egroupware-felamimail_1.0.0.007-2.dfsg-2sarge4\n');
}
if (deb_check(prefix: 'egroupware-filemanager', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package egroupware-filemanager is vulnerable in Debian 3.1.\nUpgrade to egroupware-filemanager_1.0.0.007-2.dfsg-2sarge4\n');
}
if (deb_check(prefix: 'egroupware-forum', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package egroupware-forum is vulnerable in Debian 3.1.\nUpgrade to egroupware-forum_1.0.0.007-2.dfsg-2sarge4\n');
}
if (deb_check(prefix: 'egroupware-ftp', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package egroupware-ftp is vulnerable in Debian 3.1.\nUpgrade to egroupware-ftp_1.0.0.007-2.dfsg-2sarge4\n');
}
if (deb_check(prefix: 'egroupware-fudforum', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package egroupware-fudforum is vulnerable in Debian 3.1.\nUpgrade to egroupware-fudforum_1.0.0.007-2.dfsg-2sarge4\n');
}
if (deb_check(prefix: 'egroupware-headlines', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package egroupware-headlines is vulnerable in Debian 3.1.\nUpgrade to egroupware-headlines_1.0.0.007-2.dfsg-2sarge4\n');
}
if (deb_check(prefix: 'egroupware-infolog', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package egroupware-infolog is vulnerable in Debian 3.1.\nUpgrade to egroupware-infolog_1.0.0.007-2.dfsg-2sarge4\n');
}
if (deb_check(prefix: 'egroupware-jinn', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package egroupware-jinn is vulnerable in Debian 3.1.\nUpgrade to egroupware-jinn_1.0.0.007-2.dfsg-2sarge4\n');
}
if (deb_check(prefix: 'egroupware-ldap', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package egroupware-ldap is vulnerable in Debian 3.1.\nUpgrade to egroupware-ldap_1.0.0.007-2.dfsg-2sarge4\n');
}
if (deb_check(prefix: 'egroupware-manual', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package egroupware-manual is vulnerable in Debian 3.1.\nUpgrade to egroupware-manual_1.0.0.007-2.dfsg-2sarge4\n');
}
if (deb_check(prefix: 'egroupware-messenger', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package egroupware-messenger is vulnerable in Debian 3.1.\nUpgrade to egroupware-messenger_1.0.0.007-2.dfsg-2sarge4\n');
}
if (deb_check(prefix: 'egroupware-news-admin', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package egroupware-news-admin is vulnerable in Debian 3.1.\nUpgrade to egroupware-news-admin_1.0.0.007-2.dfsg-2sarge4\n');
}
if (deb_check(prefix: 'egroupware-phpbrain', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package egroupware-phpbrain is vulnerable in Debian 3.1.\nUpgrade to egroupware-phpbrain_1.0.0.007-2.dfsg-2sarge4\n');
}
if (deb_check(prefix: 'egroupware-phpldapadmin', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package egroupware-phpldapadmin is vulnerable in Debian 3.1.\nUpgrade to egroupware-phpldapadmin_1.0.0.007-2.dfsg-2sarge4\n');
}
if (deb_check(prefix: 'egroupware-phpsysinfo', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package egroupware-phpsysinfo is vulnerable in Debian 3.1.\nUpgrade to egroupware-phpsysinfo_1.0.0.007-2.dfsg-2sarge4\n');
}
if (deb_check(prefix: 'egroupware-polls', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package egroupware-polls is vulnerable in Debian 3.1.\nUpgrade to egroupware-polls_1.0.0.007-2.dfsg-2sarge4\n');
}
if (deb_check(prefix: 'egroupware-projects', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package egroupware-projects is vulnerable in Debian 3.1.\nUpgrade to egroupware-projects_1.0.0.007-2.dfsg-2sarge4\n');
}
if (deb_check(prefix: 'egroupware-registration', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package egroupware-registration is vulnerable in Debian 3.1.\nUpgrade to egroupware-registration_1.0.0.007-2.dfsg-2sarge4\n');
}
if (deb_check(prefix: 'egroupware-sitemgr', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package egroupware-sitemgr is vulnerable in Debian 3.1.\nUpgrade to egroupware-sitemgr_1.0.0.007-2.dfsg-2sarge4\n');
}
if (deb_check(prefix: 'egroupware-stocks', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package egroupware-stocks is vulnerable in Debian 3.1.\nUpgrade to egroupware-stocks_1.0.0.007-2.dfsg-2sarge4\n');
}
if (deb_check(prefix: 'egroupware-tts', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package egroupware-tts is vulnerable in Debian 3.1.\nUpgrade to egroupware-tts_1.0.0.007-2.dfsg-2sarge4\n');
}
if (deb_check(prefix: 'egroupware-wiki', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package egroupware-wiki is vulnerable in Debian 3.1.\nUpgrade to egroupware-wiki_1.0.0.007-2.dfsg-2sarge4\n');
}
if (deb_check(prefix: 'egroupware', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package egroupware is vulnerable in Debian sarge.\nUpgrade to egroupware_1.0.0.007-2.dfsg-2sarge4\n');
}
if (w) { security_hole(port: 0, data: desc); }
