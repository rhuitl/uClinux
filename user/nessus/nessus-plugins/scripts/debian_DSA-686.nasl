# This script was automatically generated from the dsa-686
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Albert Puigsech Galicia discovered a directory traversal vulnerability
in a proprietary FTP client (CVE-2004-1376) which is also present in
gftp, a GTK+ FTP client.  A malicious server could provide a specially
crafted filename that could cause arbitrary files to be overwritten or
created by the client.
For the stable distribution (woody) this problem has been fixed in
version 2.0.11-1woody1.
For the unstable distribution (sid) this problem has been fixed in
version 2.0.18-1.
We recommend that you upgrade your gftp package.


Solution : http://www.debian.org/security/2005/dsa-686
Risk factor : High';

if (description) {
 script_id(17136);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "686");
 script_cve_id("CVE-2005-0372");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA686] DSA-686-1 gftp");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-686-1 gftp");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gftp', release: '3.0', reference: '2.0.11-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gftp is vulnerable in Debian 3.0.\nUpgrade to gftp_2.0.11-1woody1\n');
}
if (deb_check(prefix: 'gftp-common', release: '3.0', reference: '2.0.11-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gftp-common is vulnerable in Debian 3.0.\nUpgrade to gftp-common_2.0.11-1woody1\n');
}
if (deb_check(prefix: 'gftp-gtk', release: '3.0', reference: '2.0.11-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gftp-gtk is vulnerable in Debian 3.0.\nUpgrade to gftp-gtk_2.0.11-1woody1\n');
}
if (deb_check(prefix: 'gftp-text', release: '3.0', reference: '2.0.11-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gftp-text is vulnerable in Debian 3.0.\nUpgrade to gftp-text_2.0.11-1woody1\n');
}
if (deb_check(prefix: 'gftp', release: '3.1', reference: '2.0.18-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gftp is vulnerable in Debian 3.1.\nUpgrade to gftp_2.0.18-1\n');
}
if (deb_check(prefix: 'gftp', release: '3.0', reference: '2.0.11-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gftp is vulnerable in Debian woody.\nUpgrade to gftp_2.0.11-1woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
