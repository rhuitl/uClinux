# This script was automatically generated from the dsa-798
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several vulnerabilities have been discovered in phpgroupware, a web
based groupware system written in PHP.  The Common Vulnerabilities and
Exposures project identifies the following problems:
    Stefan Esser discovered another vulnerability in the XML-RPC
    libraries that allows injection of arbitrary PHP code into eval()
    statements.  The XMLRPC component has been disabled.
    Alexander Heidenreich discovered a cross-site scripting problem
    in the tree view of FUD Forum Bulletin Board Software, which is
    also present in phpgroupware.
    A global cross-site scripting fix has also been included that
    protects against potential malicious scripts embedded in CSS and
    xmlns in various parts of the application and modules.
This update also contains a postinst bugfix that has been approved for
the next update to the stable release.
For the old stable distribution (woody) these problems don\'t apply.
For the stable distribution (sarge) these problems have been fixed in
version 0.9.16.005-3.sarge2.
For the unstable distribution (sid) these problems have been fixed in
version 0.9.16.008.
We recommend that you upgrade your phpgroupware packages.


Solution : http://www.debian.org/security/2005/dsa-798
Risk factor : High';

if (description) {
 script_id(19568);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "798");
 script_cve_id("CVE-2005-2498", "CVE-2005-2600", "CVE-2005-2761");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA798] DSA-798-1 phpgroupware");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-798-1 phpgroupware");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'phpgroupware', release: '', reference: '0.9.16.008')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware is vulnerable in Debian .\nUpgrade to phpgroupware_0.9.16.008\n');
}
if (deb_check(prefix: 'phpgroupware', release: '3.1', reference: '0.9.16.005-3.sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware is vulnerable in Debian 3.1.\nUpgrade to phpgroupware_0.9.16.005-3.sarge2\n');
}
if (deb_check(prefix: 'phpgroupware-addressbook', release: '3.1', reference: '0.9.16.005-3.sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-addressbook is vulnerable in Debian 3.1.\nUpgrade to phpgroupware-addressbook_0.9.16.005-3.sarge2\n');
}
if (deb_check(prefix: 'phpgroupware-admin', release: '3.1', reference: '0.9.16.005-3.sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-admin is vulnerable in Debian 3.1.\nUpgrade to phpgroupware-admin_0.9.16.005-3.sarge2\n');
}
if (deb_check(prefix: 'phpgroupware-bookmarks', release: '3.1', reference: '0.9.16.005-3.sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-bookmarks is vulnerable in Debian 3.1.\nUpgrade to phpgroupware-bookmarks_0.9.16.005-3.sarge2\n');
}
if (deb_check(prefix: 'phpgroupware-calendar', release: '3.1', reference: '0.9.16.005-3.sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-calendar is vulnerable in Debian 3.1.\nUpgrade to phpgroupware-calendar_0.9.16.005-3.sarge2\n');
}
if (deb_check(prefix: 'phpgroupware-chat', release: '3.1', reference: '0.9.16.005-3.sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-chat is vulnerable in Debian 3.1.\nUpgrade to phpgroupware-chat_0.9.16.005-3.sarge2\n');
}
if (deb_check(prefix: 'phpgroupware-comic', release: '3.1', reference: '0.9.16.005-3.sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-comic is vulnerable in Debian 3.1.\nUpgrade to phpgroupware-comic_0.9.16.005-3.sarge2\n');
}
if (deb_check(prefix: 'phpgroupware-core', release: '3.1', reference: '0.9.16.005-3.sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-core is vulnerable in Debian 3.1.\nUpgrade to phpgroupware-core_0.9.16.005-3.sarge2\n');
}
if (deb_check(prefix: 'phpgroupware-developer-tools', release: '3.1', reference: '0.9.16.005-3.sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-developer-tools is vulnerable in Debian 3.1.\nUpgrade to phpgroupware-developer-tools_0.9.16.005-3.sarge2\n');
}
if (deb_check(prefix: 'phpgroupware-dj', release: '3.1', reference: '0.9.16.005-3.sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-dj is vulnerable in Debian 3.1.\nUpgrade to phpgroupware-dj_0.9.16.005-3.sarge2\n');
}
if (deb_check(prefix: 'phpgroupware-eldaptir', release: '3.1', reference: '0.9.16.005-3.sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-eldaptir is vulnerable in Debian 3.1.\nUpgrade to phpgroupware-eldaptir_0.9.16.005-3.sarge2\n');
}
if (deb_check(prefix: 'phpgroupware-email', release: '3.1', reference: '0.9.16.005-3.sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-email is vulnerable in Debian 3.1.\nUpgrade to phpgroupware-email_0.9.16.005-3.sarge2\n');
}
if (deb_check(prefix: 'phpgroupware-etemplate', release: '3.1', reference: '0.9.16.005-3.sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-etemplate is vulnerable in Debian 3.1.\nUpgrade to phpgroupware-etemplate_0.9.16.005-3.sarge2\n');
}
if (deb_check(prefix: 'phpgroupware-felamimail', release: '3.1', reference: '0.9.16.005-3.sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-felamimail is vulnerable in Debian 3.1.\nUpgrade to phpgroupware-felamimail_0.9.16.005-3.sarge2\n');
}
if (deb_check(prefix: 'phpgroupware-filemanager', release: '3.1', reference: '0.9.16.005-3.sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-filemanager is vulnerable in Debian 3.1.\nUpgrade to phpgroupware-filemanager_0.9.16.005-3.sarge2\n');
}
if (deb_check(prefix: 'phpgroupware-folders', release: '3.1', reference: '0.9.16.005-3.sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-folders is vulnerable in Debian 3.1.\nUpgrade to phpgroupware-folders_0.9.16.005-3.sarge2\n');
}
if (deb_check(prefix: 'phpgroupware-forum', release: '3.1', reference: '0.9.16.005-3.sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-forum is vulnerable in Debian 3.1.\nUpgrade to phpgroupware-forum_0.9.16.005-3.sarge2\n');
}
if (deb_check(prefix: 'phpgroupware-ftp', release: '3.1', reference: '0.9.16.005-3.sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-ftp is vulnerable in Debian 3.1.\nUpgrade to phpgroupware-ftp_0.9.16.005-3.sarge2\n');
}
if (deb_check(prefix: 'phpgroupware-fudforum', release: '3.1', reference: '0.9.16.005-3.sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-fudforum is vulnerable in Debian 3.1.\nUpgrade to phpgroupware-fudforum_0.9.16.005-3.sarge2\n');
}
if (deb_check(prefix: 'phpgroupware-headlines', release: '3.1', reference: '0.9.16.005-3.sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-headlines is vulnerable in Debian 3.1.\nUpgrade to phpgroupware-headlines_0.9.16.005-3.sarge2\n');
}
if (deb_check(prefix: 'phpgroupware-hr', release: '3.1', reference: '0.9.16.005-3.sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-hr is vulnerable in Debian 3.1.\nUpgrade to phpgroupware-hr_0.9.16.005-3.sarge2\n');
}
if (deb_check(prefix: 'phpgroupware-img', release: '3.1', reference: '0.9.16.005-3.sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-img is vulnerable in Debian 3.1.\nUpgrade to phpgroupware-img_0.9.16.005-3.sarge2\n');
}
if (deb_check(prefix: 'phpgroupware-infolog', release: '3.1', reference: '0.9.16.005-3.sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-infolog is vulnerable in Debian 3.1.\nUpgrade to phpgroupware-infolog_0.9.16.005-3.sarge2\n');
}
if (deb_check(prefix: 'phpgroupware-manual', release: '3.1', reference: '0.9.16.005-3.sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-manual is vulnerable in Debian 3.1.\nUpgrade to phpgroupware-manual_0.9.16.005-3.sarge2\n');
}
if (deb_check(prefix: 'phpgroupware-messenger', release: '3.1', reference: '0.9.16.005-3.sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-messenger is vulnerable in Debian 3.1.\nUpgrade to phpgroupware-messenger_0.9.16.005-3.sarge2\n');
}
if (deb_check(prefix: 'phpgroupware-news-admin', release: '3.1', reference: '0.9.16.005-3.sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-news-admin is vulnerable in Debian 3.1.\nUpgrade to phpgroupware-news-admin_0.9.16.005-3.sarge2\n');
}
if (deb_check(prefix: 'phpgroupware-nntp', release: '3.1', reference: '0.9.16.005-3.sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-nntp is vulnerable in Debian 3.1.\nUpgrade to phpgroupware-nntp_0.9.16.005-3.sarge2\n');
}
if (deb_check(prefix: 'phpgroupware-notes', release: '3.1', reference: '0.9.16.005-3.sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-notes is vulnerable in Debian 3.1.\nUpgrade to phpgroupware-notes_0.9.16.005-3.sarge2\n');
}
if (deb_check(prefix: 'phpgroupware-phonelog', release: '3.1', reference: '0.9.16.005-3.sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-phonelog is vulnerable in Debian 3.1.\nUpgrade to phpgroupware-phonelog_0.9.16.005-3.sarge2\n');
}
if (deb_check(prefix: 'phpgroupware-phpbrain', release: '3.1', reference: '0.9.16.005-3.sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-phpbrain is vulnerable in Debian 3.1.\nUpgrade to phpgroupware-phpbrain_0.9.16.005-3.sarge2\n');
}
if (deb_check(prefix: 'phpgroupware-phpgwapi', release: '3.1', reference: '0.9.16.005-3.sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-phpgwapi is vulnerable in Debian 3.1.\nUpgrade to phpgroupware-phpgwapi_0.9.16.005-3.sarge2\n');
}
if (deb_check(prefix: 'phpgroupware-phpsysinfo', release: '3.1', reference: '0.9.16.005-3.sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-phpsysinfo is vulnerable in Debian 3.1.\nUpgrade to phpgroupware-phpsysinfo_0.9.16.005-3.sarge2\n');
}
if (deb_check(prefix: 'phpgroupware-polls', release: '3.1', reference: '0.9.16.005-3.sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-polls is vulnerable in Debian 3.1.\nUpgrade to phpgroupware-polls_0.9.16.005-3.sarge2\n');
}
if (deb_check(prefix: 'phpgroupware-preferences', release: '3.1', reference: '0.9.16.005-3.sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-preferences is vulnerable in Debian 3.1.\nUpgrade to phpgroupware-preferences_0.9.16.005-3.sarge2\n');
}
if (deb_check(prefix: 'phpgroupware-projects', release: '3.1', reference: '0.9.16.005-3.sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-projects is vulnerable in Debian 3.1.\nUpgrade to phpgroupware-projects_0.9.16.005-3.sarge2\n');
}
if (deb_check(prefix: 'phpgroupware-qmailldap', release: '3.1', reference: '0.9.16.005-3.sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-qmailldap is vulnerable in Debian 3.1.\nUpgrade to phpgroupware-qmailldap_0.9.16.005-3.sarge2\n');
}
if (deb_check(prefix: 'phpgroupware-registration', release: '3.1', reference: '0.9.16.005-3.sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-registration is vulnerable in Debian 3.1.\nUpgrade to phpgroupware-registration_0.9.16.005-3.sarge2\n');
}
if (deb_check(prefix: 'phpgroupware-setup', release: '3.1', reference: '0.9.16.005-3.sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-setup is vulnerable in Debian 3.1.\nUpgrade to phpgroupware-setup_0.9.16.005-3.sarge2\n');
}
if (deb_check(prefix: 'phpgroupware-sitemgr', release: '3.1', reference: '0.9.16.005-3.sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-sitemgr is vulnerable in Debian 3.1.\nUpgrade to phpgroupware-sitemgr_0.9.16.005-3.sarge2\n');
}
if (deb_check(prefix: 'phpgroupware-skel', release: '3.1', reference: '0.9.16.005-3.sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-skel is vulnerable in Debian 3.1.\nUpgrade to phpgroupware-skel_0.9.16.005-3.sarge2\n');
}
if (deb_check(prefix: 'phpgroupware-soap', release: '3.1', reference: '0.9.16.005-3.sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-soap is vulnerable in Debian 3.1.\nUpgrade to phpgroupware-soap_0.9.16.005-3.sarge2\n');
}
if (deb_check(prefix: 'phpgroupware-stocks', release: '3.1', reference: '0.9.16.005-3.sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-stocks is vulnerable in Debian 3.1.\nUpgrade to phpgroupware-stocks_0.9.16.005-3.sarge2\n');
}
if (deb_check(prefix: 'phpgroupware-todo', release: '3.1', reference: '0.9.16.005-3.sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-todo is vulnerable in Debian 3.1.\nUpgrade to phpgroupware-todo_0.9.16.005-3.sarge2\n');
}
if (deb_check(prefix: 'phpgroupware-tts', release: '3.1', reference: '0.9.16.005-3.sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-tts is vulnerable in Debian 3.1.\nUpgrade to phpgroupware-tts_0.9.16.005-3.sarge2\n');
}
if (deb_check(prefix: 'phpgroupware-wiki', release: '3.1', reference: '0.9.16.005-3.sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-wiki is vulnerable in Debian 3.1.\nUpgrade to phpgroupware-wiki_0.9.16.005-3.sarge2\n');
}
if (deb_check(prefix: 'phpgroupware-xmlrpc', release: '3.1', reference: '0.9.16.005-3.sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-xmlrpc is vulnerable in Debian 3.1.\nUpgrade to phpgroupware-xmlrpc_0.9.16.005-3.sarge2\n');
}
if (deb_check(prefix: 'phpgroupware', release: '3.1', reference: '0.9.16.005-3.sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware is vulnerable in Debian sarge.\nUpgrade to phpgroupware_0.9.16.005-3.sarge2\n');
}
if (w) { security_hole(port: 0, data: desc); }
