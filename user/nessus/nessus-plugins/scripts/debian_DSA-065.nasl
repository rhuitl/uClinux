# This script was automatically generated from the dsa-065
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Michal Zalewski discovered that Samba does not properly validate
NetBIOS names from remote machines.

By itself that is not a problem, except if Samba is configured to
write log-files to a file that includes the NetBIOS name of the
remote side by using the `%m\' macro in the `log file\' command. In
that case an attacker could use a NetBIOS name like \'../tmp/evil\'.
If the log-file was set to "/var/log/samba/%s" Samba would then
write to /var/tmp/evil.

Since the NetBIOS name is limited to 15 characters and the `log
file\' command could have an extension to the filename the results
of this are limited. However if the attacker is also able to create
symbolic links on the Samba server they could trick Samba into
appending any data they want to all files on the filesystem which
Samba can write to.

The Debian GNU/Linux packaged version of Samba has a safe
configuration and is not vulnerable.

As temporary workaround for systems that are vulnerable change all
occurrences of the `%m\' macro in smb.conf to `%l\' and restart Samba.

This has been fixed in version 2.0.7-3.4, and we recommend that you
upgrade your Samba package immediately.



Solution : http://www.debian.org/security/2001/dsa-065
Risk factor : High';

if (description) {
 script_id(14902);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "065");
 script_cve_id("CVE-2001-1162");
 script_bugtraq_id(2927);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA065] DSA-065-1 samba");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-065-1 samba");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'samba', release: '2.2', reference: '2.0.7-3.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package samba is vulnerable in Debian 2.2.\nUpgrade to samba_2.0.7-3.4\n');
}
if (deb_check(prefix: 'samba-common', release: '2.2', reference: '2.0.7-3.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package samba-common is vulnerable in Debian 2.2.\nUpgrade to samba-common_2.0.7-3.4\n');
}
if (deb_check(prefix: 'samba-doc', release: '2.2', reference: '2.0.7-3.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package samba-doc is vulnerable in Debian 2.2.\nUpgrade to samba-doc_2.0.7-3.4\n');
}
if (deb_check(prefix: 'smbclient', release: '2.2', reference: '2.0.7-3.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package smbclient is vulnerable in Debian 2.2.\nUpgrade to smbclient_2.0.7-3.4\n');
}
if (deb_check(prefix: 'smbfs', release: '2.2', reference: '2.0.7-3.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package smbfs is vulnerable in Debian 2.2.\nUpgrade to smbfs_2.0.7-3.4\n');
}
if (deb_check(prefix: 'swat', release: '2.2', reference: '2.0.7-3.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package swat is vulnerable in Debian 2.2.\nUpgrade to swat_2.0.7-3.4\n');
}
if (w) { security_hole(port: 0, data: desc); }
