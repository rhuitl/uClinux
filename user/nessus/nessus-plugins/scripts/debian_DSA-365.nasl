# This script was automatically generated from the dsa-365
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several vulnerabilities have been discovered in phpgroupware:
For the stable distribution (woody), these problems have been fixed in
version 0.9.14-0.RC3.2.woody2.
For the unstable distribution (sid), these problems will be fixed
soon.  Refer to Debian bug #201980.
We recommend that you update your phpgroupware package.


Solution : http://www.debian.org/security/2003/dsa-365
Risk factor : High';

if (description) {
 script_id(15202);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "365");
 script_cve_id("CVE-2003-0504", "CVE-2003-0599", "CVE-2003-0657");
 script_bugtraq_id(8088);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA365] DSA-365-1 phpgroupware");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-365-1 phpgroupware");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'phpgroupware', release: '3.0', reference: '0.9.14-0.RC3.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware is vulnerable in Debian 3.0.\nUpgrade to phpgroupware_0.9.14-0.RC3.2.woody2\n');
}
if (deb_check(prefix: 'phpgroupware-addressbook', release: '3.0', reference: '0.9.14-0.RC3.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-addressbook is vulnerable in Debian 3.0.\nUpgrade to phpgroupware-addressbook_0.9.14-0.RC3.2.woody2\n');
}
if (deb_check(prefix: 'phpgroupware-admin', release: '3.0', reference: '0.9.14-0.RC3.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-admin is vulnerable in Debian 3.0.\nUpgrade to phpgroupware-admin_0.9.14-0.RC3.2.woody2\n');
}
if (deb_check(prefix: 'phpgroupware-api', release: '3.0', reference: '0.9.14-0.RC3.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-api is vulnerable in Debian 3.0.\nUpgrade to phpgroupware-api_0.9.14-0.RC3.2.woody2\n');
}
if (deb_check(prefix: 'phpgroupware-api-doc', release: '3.0', reference: '0.9.14-0.RC3.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-api-doc is vulnerable in Debian 3.0.\nUpgrade to phpgroupware-api-doc_0.9.14-0.RC3.2.woody2\n');
}
if (deb_check(prefix: 'phpgroupware-bookkeeping', release: '3.0', reference: '0.9.14-0.RC3.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-bookkeeping is vulnerable in Debian 3.0.\nUpgrade to phpgroupware-bookkeeping_0.9.14-0.RC3.2.woody2\n');
}
if (deb_check(prefix: 'phpgroupware-bookmarks', release: '3.0', reference: '0.9.14-0.RC3.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-bookmarks is vulnerable in Debian 3.0.\nUpgrade to phpgroupware-bookmarks_0.9.14-0.RC3.2.woody2\n');
}
if (deb_check(prefix: 'phpgroupware-brewer', release: '3.0', reference: '0.9.14-0.RC3.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-brewer is vulnerable in Debian 3.0.\nUpgrade to phpgroupware-brewer_0.9.14-0.RC3.2.woody2\n');
}
if (deb_check(prefix: 'phpgroupware-calendar', release: '3.0', reference: '0.9.14-0.RC3.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-calendar is vulnerable in Debian 3.0.\nUpgrade to phpgroupware-calendar_0.9.14-0.RC3.2.woody2\n');
}
if (deb_check(prefix: 'phpgroupware-chat', release: '3.0', reference: '0.9.14-0.RC3.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-chat is vulnerable in Debian 3.0.\nUpgrade to phpgroupware-chat_0.9.14-0.RC3.2.woody2\n');
}
if (deb_check(prefix: 'phpgroupware-chora', release: '3.0', reference: '0.9.14-0.RC3.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-chora is vulnerable in Debian 3.0.\nUpgrade to phpgroupware-chora_0.9.14-0.RC3.2.woody2\n');
}
if (deb_check(prefix: 'phpgroupware-comic', release: '3.0', reference: '0.9.14-0.RC3.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-comic is vulnerable in Debian 3.0.\nUpgrade to phpgroupware-comic_0.9.14-0.RC3.2.woody2\n');
}
if (deb_check(prefix: 'phpgroupware-core', release: '3.0', reference: '0.9.14-0.RC3.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-core is vulnerable in Debian 3.0.\nUpgrade to phpgroupware-core_0.9.14-0.RC3.2.woody2\n');
}
if (deb_check(prefix: 'phpgroupware-core-doc', release: '3.0', reference: '0.9.14-0.RC3.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-core-doc is vulnerable in Debian 3.0.\nUpgrade to phpgroupware-core-doc_0.9.14-0.RC3.2.woody2\n');
}
if (deb_check(prefix: 'phpgroupware-developer-tools', release: '3.0', reference: '0.9.14-0.RC3.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-developer-tools is vulnerable in Debian 3.0.\nUpgrade to phpgroupware-developer-tools_0.9.14-0.RC3.2.woody2\n');
}
if (deb_check(prefix: 'phpgroupware-dj', release: '3.0', reference: '0.9.14-0.RC3.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-dj is vulnerable in Debian 3.0.\nUpgrade to phpgroupware-dj_0.9.14-0.RC3.2.woody2\n');
}
if (deb_check(prefix: 'phpgroupware-eldaptir', release: '3.0', reference: '0.9.14-0.RC3.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-eldaptir is vulnerable in Debian 3.0.\nUpgrade to phpgroupware-eldaptir_0.9.14-0.RC3.2.woody2\n');
}
if (deb_check(prefix: 'phpgroupware-email', release: '3.0', reference: '0.9.14-0.RC3.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-email is vulnerable in Debian 3.0.\nUpgrade to phpgroupware-email_0.9.14-0.RC3.2.woody2\n');
}
if (deb_check(prefix: 'phpgroupware-filemanager', release: '3.0', reference: '0.9.14-0.RC3.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-filemanager is vulnerable in Debian 3.0.\nUpgrade to phpgroupware-filemanager_0.9.14-0.RC3.2.woody2\n');
}
if (deb_check(prefix: 'phpgroupware-forum', release: '3.0', reference: '0.9.14-0.RC3.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-forum is vulnerable in Debian 3.0.\nUpgrade to phpgroupware-forum_0.9.14-0.RC3.2.woody2\n');
}
if (deb_check(prefix: 'phpgroupware-ftp', release: '3.0', reference: '0.9.14-0.RC3.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-ftp is vulnerable in Debian 3.0.\nUpgrade to phpgroupware-ftp_0.9.14-0.RC3.2.woody2\n');
}
if (deb_check(prefix: 'phpgroupware-headlines', release: '3.0', reference: '0.9.14-0.RC3.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-headlines is vulnerable in Debian 3.0.\nUpgrade to phpgroupware-headlines_0.9.14-0.RC3.2.woody2\n');
}
if (deb_check(prefix: 'phpgroupware-hr', release: '3.0', reference: '0.9.14-0.RC3.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-hr is vulnerable in Debian 3.0.\nUpgrade to phpgroupware-hr_0.9.14-0.RC3.2.woody2\n');
}
if (deb_check(prefix: 'phpgroupware-img', release: '3.0', reference: '0.9.14-0.RC3.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-img is vulnerable in Debian 3.0.\nUpgrade to phpgroupware-img_0.9.14-0.RC3.2.woody2\n');
}
if (deb_check(prefix: 'phpgroupware-infolog', release: '3.0', reference: '0.9.14-0.RC3.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-infolog is vulnerable in Debian 3.0.\nUpgrade to phpgroupware-infolog_0.9.14-0.RC3.2.woody2\n');
}
if (deb_check(prefix: 'phpgroupware-inv', release: '3.0', reference: '0.9.14-0.RC3.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-inv is vulnerable in Debian 3.0.\nUpgrade to phpgroupware-inv_0.9.14-0.RC3.2.woody2\n');
}
if (deb_check(prefix: 'phpgroupware-manual', release: '3.0', reference: '0.9.14-0.RC3.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-manual is vulnerable in Debian 3.0.\nUpgrade to phpgroupware-manual_0.9.14-0.RC3.2.woody2\n');
}
if (deb_check(prefix: 'phpgroupware-messenger', release: '3.0', reference: '0.9.14-0.RC3.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-messenger is vulnerable in Debian 3.0.\nUpgrade to phpgroupware-messenger_0.9.14-0.RC3.2.woody2\n');
}
if (deb_check(prefix: 'phpgroupware-napster', release: '3.0', reference: '0.9.14-0.RC3.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-napster is vulnerable in Debian 3.0.\nUpgrade to phpgroupware-napster_0.9.14-0.RC3.2.woody2\n');
}
if (deb_check(prefix: 'phpgroupware-news-admin', release: '3.0', reference: '0.9.14-0.RC3.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-news-admin is vulnerable in Debian 3.0.\nUpgrade to phpgroupware-news-admin_0.9.14-0.RC3.2.woody2\n');
}
if (deb_check(prefix: 'phpgroupware-nntp', release: '3.0', reference: '0.9.14-0.RC3.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-nntp is vulnerable in Debian 3.0.\nUpgrade to phpgroupware-nntp_0.9.14-0.RC3.2.woody2\n');
}
if (deb_check(prefix: 'phpgroupware-notes', release: '3.0', reference: '0.9.14-0.RC3.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-notes is vulnerable in Debian 3.0.\nUpgrade to phpgroupware-notes_0.9.14-0.RC3.2.woody2\n');
}
if (deb_check(prefix: 'phpgroupware-phonelog', release: '3.0', reference: '0.9.14-0.RC3.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-phonelog is vulnerable in Debian 3.0.\nUpgrade to phpgroupware-phonelog_0.9.14-0.RC3.2.woody2\n');
}
if (deb_check(prefix: 'phpgroupware-phpsysinfo', release: '3.0', reference: '0.9.14-0.RC3.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-phpsysinfo is vulnerable in Debian 3.0.\nUpgrade to phpgroupware-phpsysinfo_0.9.14-0.RC3.2.woody2\n');
}
if (deb_check(prefix: 'phpgroupware-phpwebhosting', release: '3.0', reference: '0.9.14-0.RC3.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-phpwebhosting is vulnerable in Debian 3.0.\nUpgrade to phpgroupware-phpwebhosting_0.9.14-0.RC3.2.woody2\n');
}
if (deb_check(prefix: 'phpgroupware-polls', release: '3.0', reference: '0.9.14-0.RC3.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-polls is vulnerable in Debian 3.0.\nUpgrade to phpgroupware-polls_0.9.14-0.RC3.2.woody2\n');
}
if (deb_check(prefix: 'phpgroupware-preferences', release: '3.0', reference: '0.9.14-0.RC3.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-preferences is vulnerable in Debian 3.0.\nUpgrade to phpgroupware-preferences_0.9.14-0.RC3.2.woody2\n');
}
if (deb_check(prefix: 'phpgroupware-projects', release: '3.0', reference: '0.9.14-0.RC3.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-projects is vulnerable in Debian 3.0.\nUpgrade to phpgroupware-projects_0.9.14-0.RC3.2.woody2\n');
}
if (deb_check(prefix: 'phpgroupware-registration', release: '3.0', reference: '0.9.14-0.RC3.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-registration is vulnerable in Debian 3.0.\nUpgrade to phpgroupware-registration_0.9.14-0.RC3.2.woody2\n');
}
if (deb_check(prefix: 'phpgroupware-setup', release: '3.0', reference: '0.9.14-0.RC3.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-setup is vulnerable in Debian 3.0.\nUpgrade to phpgroupware-setup_0.9.14-0.RC3.2.woody2\n');
}
if (deb_check(prefix: 'phpgroupware-skel', release: '3.0', reference: '0.9.14-0.RC3.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-skel is vulnerable in Debian 3.0.\nUpgrade to phpgroupware-skel_0.9.14-0.RC3.2.woody2\n');
}
if (deb_check(prefix: 'phpgroupware-soap', release: '3.0', reference: '0.9.14-0.RC3.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-soap is vulnerable in Debian 3.0.\nUpgrade to phpgroupware-soap_0.9.14-0.RC3.2.woody2\n');
}
if (deb_check(prefix: 'phpgroupware-stocks', release: '3.0', reference: '0.9.14-0.RC3.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-stocks is vulnerable in Debian 3.0.\nUpgrade to phpgroupware-stocks_0.9.14-0.RC3.2.woody2\n');
}
if (deb_check(prefix: 'phpgroupware-todo', release: '3.0', reference: '0.9.14-0.RC3.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-todo is vulnerable in Debian 3.0.\nUpgrade to phpgroupware-todo_0.9.14-0.RC3.2.woody2\n');
}
if (deb_check(prefix: 'phpgroupware-tts', release: '3.0', reference: '0.9.14-0.RC3.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-tts is vulnerable in Debian 3.0.\nUpgrade to phpgroupware-tts_0.9.14-0.RC3.2.woody2\n');
}
if (deb_check(prefix: 'phpgroupware-wap', release: '3.0', reference: '0.9.14-0.RC3.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-wap is vulnerable in Debian 3.0.\nUpgrade to phpgroupware-wap_0.9.14-0.RC3.2.woody2\n');
}
if (deb_check(prefix: 'phpgroupware-weather', release: '3.0', reference: '0.9.14-0.RC3.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-weather is vulnerable in Debian 3.0.\nUpgrade to phpgroupware-weather_0.9.14-0.RC3.2.woody2\n');
}
if (deb_check(prefix: 'phpgroupware-xmlrpc', release: '3.0', reference: '0.9.14-0.RC3.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware-xmlrpc is vulnerable in Debian 3.0.\nUpgrade to phpgroupware-xmlrpc_0.9.14-0.RC3.2.woody2\n');
}
if (deb_check(prefix: 'phpgroupware', release: '3.0', reference: '0.9.14-0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpgroupware is vulnerable in Debian woody.\nUpgrade to phpgroupware_0.9.14-0\n');
}
if (w) { security_hole(port: 0, data: desc); }
