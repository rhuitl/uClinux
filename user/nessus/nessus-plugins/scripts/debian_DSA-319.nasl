# This script was automatically generated from the dsa-319
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
miniserv.pl in the webmin package does not properly handle
metacharacters, such as line feeds and carriage returns, in
Base64-encoded strings used in Basic authentication.  This
vulnerability allows remote attackers to spoof a session ID, and
thereby gain root privileges.
For the stable distribution (woody) this problem has been fixed in
version 0.94-7woody1.
The old stable distribution (potato) does not contain a webmin package.
For the unstable distribution (sid) this problem is fixed in version
1.070-1.
We recommend that you update your webmin package.


Solution : http://www.debian.org/security/2003/dsa-319
Risk factor : High';

if (description) {
 script_id(15156);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "319");
 script_cve_id("CVE-2003-0101");
 script_bugtraq_id(6915);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA319] DSA-319-1 webmin");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-319-1 webmin");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'webmin', release: '3.0', reference: '0.94-7woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webmin is vulnerable in Debian 3.0.\nUpgrade to webmin_0.94-7woody1\n');
}
if (deb_check(prefix: 'webmin-apache', release: '3.0', reference: '0.94-7woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webmin-apache is vulnerable in Debian 3.0.\nUpgrade to webmin-apache_0.94-7woody1\n');
}
if (deb_check(prefix: 'webmin-bind8', release: '3.0', reference: '0.94-7woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webmin-bind8 is vulnerable in Debian 3.0.\nUpgrade to webmin-bind8_0.94-7woody1\n');
}
if (deb_check(prefix: 'webmin-burner', release: '3.0', reference: '0.94-7woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webmin-burner is vulnerable in Debian 3.0.\nUpgrade to webmin-burner_0.94-7woody1\n');
}
if (deb_check(prefix: 'webmin-cluster-software', release: '3.0', reference: '0.94-7woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webmin-cluster-software is vulnerable in Debian 3.0.\nUpgrade to webmin-cluster-software_0.94-7woody1\n');
}
if (deb_check(prefix: 'webmin-cluster-useradmin', release: '3.0', reference: '0.94-7woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webmin-cluster-useradmin is vulnerable in Debian 3.0.\nUpgrade to webmin-cluster-useradmin_0.94-7woody1\n');
}
if (deb_check(prefix: 'webmin-core', release: '3.0', reference: '0.94-7woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webmin-core is vulnerable in Debian 3.0.\nUpgrade to webmin-core_0.94-7woody1\n');
}
if (deb_check(prefix: 'webmin-cpan', release: '3.0', reference: '0.94-7woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webmin-cpan is vulnerable in Debian 3.0.\nUpgrade to webmin-cpan_0.94-7woody1\n');
}
if (deb_check(prefix: 'webmin-dhcpd', release: '3.0', reference: '0.94-7woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webmin-dhcpd is vulnerable in Debian 3.0.\nUpgrade to webmin-dhcpd_0.94-7woody1\n');
}
if (deb_check(prefix: 'webmin-exports', release: '3.0', reference: '0.94-7woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webmin-exports is vulnerable in Debian 3.0.\nUpgrade to webmin-exports_0.94-7woody1\n');
}
if (deb_check(prefix: 'webmin-fetchmail', release: '3.0', reference: '0.94-7woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webmin-fetchmail is vulnerable in Debian 3.0.\nUpgrade to webmin-fetchmail_0.94-7woody1\n');
}
if (deb_check(prefix: 'webmin-grub', release: '3.0', reference: '0.94-7woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webmin-grub is vulnerable in Debian 3.0.\nUpgrade to webmin-grub_0.94-7woody1\n');
}
if (deb_check(prefix: 'webmin-heartbeat', release: '3.0', reference: '0.94-7woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webmin-heartbeat is vulnerable in Debian 3.0.\nUpgrade to webmin-heartbeat_0.94-7woody1\n');
}
if (deb_check(prefix: 'webmin-inetd', release: '3.0', reference: '0.94-7woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webmin-inetd is vulnerable in Debian 3.0.\nUpgrade to webmin-inetd_0.94-7woody1\n');
}
if (deb_check(prefix: 'webmin-jabber', release: '3.0', reference: '0.94-7woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webmin-jabber is vulnerable in Debian 3.0.\nUpgrade to webmin-jabber_0.94-7woody1\n');
}
if (deb_check(prefix: 'webmin-lpadmin', release: '3.0', reference: '0.94-7woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webmin-lpadmin is vulnerable in Debian 3.0.\nUpgrade to webmin-lpadmin_0.94-7woody1\n');
}
if (deb_check(prefix: 'webmin-mon', release: '3.0', reference: '0.94-7woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webmin-mon is vulnerable in Debian 3.0.\nUpgrade to webmin-mon_0.94-7woody1\n');
}
if (deb_check(prefix: 'webmin-mysql', release: '3.0', reference: '0.94-7woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webmin-mysql is vulnerable in Debian 3.0.\nUpgrade to webmin-mysql_0.94-7woody1\n');
}
if (deb_check(prefix: 'webmin-nis', release: '3.0', reference: '0.94-7woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webmin-nis is vulnerable in Debian 3.0.\nUpgrade to webmin-nis_0.94-7woody1\n');
}
if (deb_check(prefix: 'webmin-postfix', release: '3.0', reference: '0.94-7woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webmin-postfix is vulnerable in Debian 3.0.\nUpgrade to webmin-postfix_0.94-7woody1\n');
}
if (deb_check(prefix: 'webmin-postgresql', release: '3.0', reference: '0.94-7woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webmin-postgresql is vulnerable in Debian 3.0.\nUpgrade to webmin-postgresql_0.94-7woody1\n');
}
if (deb_check(prefix: 'webmin-ppp', release: '3.0', reference: '0.94-7woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webmin-ppp is vulnerable in Debian 3.0.\nUpgrade to webmin-ppp_0.94-7woody1\n');
}
if (deb_check(prefix: 'webmin-qmailadmin', release: '3.0', reference: '0.94-7woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webmin-qmailadmin is vulnerable in Debian 3.0.\nUpgrade to webmin-qmailadmin_0.94-7woody1\n');
}
if (deb_check(prefix: 'webmin-quota', release: '3.0', reference: '0.94-7woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webmin-quota is vulnerable in Debian 3.0.\nUpgrade to webmin-quota_0.94-7woody1\n');
}
if (deb_check(prefix: 'webmin-raid', release: '3.0', reference: '0.94-7woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webmin-raid is vulnerable in Debian 3.0.\nUpgrade to webmin-raid_0.94-7woody1\n');
}
if (deb_check(prefix: 'webmin-samba', release: '3.0', reference: '0.94-7woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webmin-samba is vulnerable in Debian 3.0.\nUpgrade to webmin-samba_0.94-7woody1\n');
}
if (deb_check(prefix: 'webmin-sendmail', release: '3.0', reference: '0.94-7woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webmin-sendmail is vulnerable in Debian 3.0.\nUpgrade to webmin-sendmail_0.94-7woody1\n');
}
if (deb_check(prefix: 'webmin-software', release: '3.0', reference: '0.94-7woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webmin-software is vulnerable in Debian 3.0.\nUpgrade to webmin-software_0.94-7woody1\n');
}
if (deb_check(prefix: 'webmin-squid', release: '3.0', reference: '0.94-7woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webmin-squid is vulnerable in Debian 3.0.\nUpgrade to webmin-squid_0.94-7woody1\n');
}
if (deb_check(prefix: 'webmin-sshd', release: '3.0', reference: '0.94-7woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webmin-sshd is vulnerable in Debian 3.0.\nUpgrade to webmin-sshd_0.94-7woody1\n');
}
if (deb_check(prefix: 'webmin-ssl', release: '3.0', reference: '0.94-7woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webmin-ssl is vulnerable in Debian 3.0.\nUpgrade to webmin-ssl_0.94-7woody1\n');
}
if (deb_check(prefix: 'webmin-status', release: '3.0', reference: '0.94-7woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webmin-status is vulnerable in Debian 3.0.\nUpgrade to webmin-status_0.94-7woody1\n');
}
if (deb_check(prefix: 'webmin-stunnel', release: '3.0', reference: '0.94-7woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webmin-stunnel is vulnerable in Debian 3.0.\nUpgrade to webmin-stunnel_0.94-7woody1\n');
}
if (deb_check(prefix: 'webmin-wuftpd', release: '3.0', reference: '0.94-7woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webmin-wuftpd is vulnerable in Debian 3.0.\nUpgrade to webmin-wuftpd_0.94-7woody1\n');
}
if (deb_check(prefix: 'webmin-xinetd', release: '3.0', reference: '0.94-7woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webmin-xinetd is vulnerable in Debian 3.0.\nUpgrade to webmin-xinetd_0.94-7woody1\n');
}
if (deb_check(prefix: 'webmin', release: '3.1', reference: '1.070-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webmin is vulnerable in Debian 3.1.\nUpgrade to webmin_1.070-1\n');
}
if (deb_check(prefix: 'webmin', release: '3.0', reference: '0.94-7woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webmin is vulnerable in Debian woody.\nUpgrade to webmin_0.94-7woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
