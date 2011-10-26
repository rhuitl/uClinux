# This script was automatically generated from the dsa-1177
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Hendrik Weimer discovered that it is possible for a normal user to
disable the login shell of the root account via usermin, a web-based
administration tool.
For the stable distribution (sarge) this problem has been fixed in
version 1.110-3.1.
In the upstream distribution this problem is fixed in version 1.220.
We recommend that you upgrade your usermin package.


Solution : http://www.debian.org/security/2006/dsa-1177
Risk factor : High';

if (description) {
 script_id(22719);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1177");
 script_cve_id("CVE-2006-4246");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1177] DSA-1177-1 usermin");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1177-1 usermin");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'usermin', release: '3.1', reference: '1.110-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package usermin is vulnerable in Debian 3.1.\nUpgrade to usermin_1.110-3.1\n');
}
if (deb_check(prefix: 'usermin-at', release: '3.1', reference: '1.110-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package usermin-at is vulnerable in Debian 3.1.\nUpgrade to usermin-at_1.110-3.1\n');
}
if (deb_check(prefix: 'usermin-changepass', release: '3.1', reference: '1.110-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package usermin-changepass is vulnerable in Debian 3.1.\nUpgrade to usermin-changepass_1.110-3.1\n');
}
if (deb_check(prefix: 'usermin-chfn', release: '3.1', reference: '1.110-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package usermin-chfn is vulnerable in Debian 3.1.\nUpgrade to usermin-chfn_1.110-3.1\n');
}
if (deb_check(prefix: 'usermin-commands', release: '3.1', reference: '1.110-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package usermin-commands is vulnerable in Debian 3.1.\nUpgrade to usermin-commands_1.110-3.1\n');
}
if (deb_check(prefix: 'usermin-cron', release: '3.1', reference: '1.110-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package usermin-cron is vulnerable in Debian 3.1.\nUpgrade to usermin-cron_1.110-3.1\n');
}
if (deb_check(prefix: 'usermin-cshrc', release: '3.1', reference: '1.110-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package usermin-cshrc is vulnerable in Debian 3.1.\nUpgrade to usermin-cshrc_1.110-3.1\n');
}
if (deb_check(prefix: 'usermin-fetchmail', release: '3.1', reference: '1.110-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package usermin-fetchmail is vulnerable in Debian 3.1.\nUpgrade to usermin-fetchmail_1.110-3.1\n');
}
if (deb_check(prefix: 'usermin-forward', release: '3.1', reference: '1.110-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package usermin-forward is vulnerable in Debian 3.1.\nUpgrade to usermin-forward_1.110-3.1\n');
}
if (deb_check(prefix: 'usermin-gnupg', release: '3.1', reference: '1.110-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package usermin-gnupg is vulnerable in Debian 3.1.\nUpgrade to usermin-gnupg_1.110-3.1\n');
}
if (deb_check(prefix: 'usermin-htaccess', release: '3.1', reference: '1.110-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package usermin-htaccess is vulnerable in Debian 3.1.\nUpgrade to usermin-htaccess_1.110-3.1\n');
}
if (deb_check(prefix: 'usermin-htpasswd', release: '3.1', reference: '1.110-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package usermin-htpasswd is vulnerable in Debian 3.1.\nUpgrade to usermin-htpasswd_1.110-3.1\n');
}
if (deb_check(prefix: 'usermin-mailbox', release: '3.1', reference: '1.110-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package usermin-mailbox is vulnerable in Debian 3.1.\nUpgrade to usermin-mailbox_1.110-3.1\n');
}
if (deb_check(prefix: 'usermin-man', release: '3.1', reference: '1.110-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package usermin-man is vulnerable in Debian 3.1.\nUpgrade to usermin-man_1.110-3.1\n');
}
if (deb_check(prefix: 'usermin-mysql', release: '3.1', reference: '1.110-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package usermin-mysql is vulnerable in Debian 3.1.\nUpgrade to usermin-mysql_1.110-3.1\n');
}
if (deb_check(prefix: 'usermin-plan', release: '3.1', reference: '1.110-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package usermin-plan is vulnerable in Debian 3.1.\nUpgrade to usermin-plan_1.110-3.1\n');
}
if (deb_check(prefix: 'usermin-postgresql', release: '3.1', reference: '1.110-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package usermin-postgresql is vulnerable in Debian 3.1.\nUpgrade to usermin-postgresql_1.110-3.1\n');
}
if (deb_check(prefix: 'usermin-proc', release: '3.1', reference: '1.110-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package usermin-proc is vulnerable in Debian 3.1.\nUpgrade to usermin-proc_1.110-3.1\n');
}
if (deb_check(prefix: 'usermin-procmail', release: '3.1', reference: '1.110-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package usermin-procmail is vulnerable in Debian 3.1.\nUpgrade to usermin-procmail_1.110-3.1\n');
}
if (deb_check(prefix: 'usermin-quota', release: '3.1', reference: '1.110-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package usermin-quota is vulnerable in Debian 3.1.\nUpgrade to usermin-quota_1.110-3.1\n');
}
if (deb_check(prefix: 'usermin-schedule', release: '3.1', reference: '1.110-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package usermin-schedule is vulnerable in Debian 3.1.\nUpgrade to usermin-schedule_1.110-3.1\n');
}
if (deb_check(prefix: 'usermin-shell', release: '3.1', reference: '1.110-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package usermin-shell is vulnerable in Debian 3.1.\nUpgrade to usermin-shell_1.110-3.1\n');
}
if (deb_check(prefix: 'usermin-spamassassin', release: '3.1', reference: '1.110-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package usermin-spamassassin is vulnerable in Debian 3.1.\nUpgrade to usermin-spamassassin_1.110-3.1\n');
}
if (deb_check(prefix: 'usermin-ssh', release: '3.1', reference: '1.110-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package usermin-ssh is vulnerable in Debian 3.1.\nUpgrade to usermin-ssh_1.110-3.1\n');
}
if (deb_check(prefix: 'usermin-tunnel', release: '3.1', reference: '1.110-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package usermin-tunnel is vulnerable in Debian 3.1.\nUpgrade to usermin-tunnel_1.110-3.1\n');
}
if (deb_check(prefix: 'usermin-updown', release: '3.1', reference: '1.110-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package usermin-updown is vulnerable in Debian 3.1.\nUpgrade to usermin-updown_1.110-3.1\n');
}
if (deb_check(prefix: 'usermin-usermount', release: '3.1', reference: '1.110-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package usermin-usermount is vulnerable in Debian 3.1.\nUpgrade to usermin-usermount_1.110-3.1\n');
}
if (deb_check(prefix: 'usermin', release: '3.1', reference: '1.110-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package usermin is vulnerable in Debian sarge.\nUpgrade to usermin_1.110-3.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
