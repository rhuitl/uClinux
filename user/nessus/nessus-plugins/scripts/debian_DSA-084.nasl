# This script was automatically generated from the dsa-084
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Stephane Gaudreault told
us that version 2.0.6a of gftp displays the
password in plain text on the screen within the log window when it is
logging into an ftp server.  A malicious colleague who is watching the
screen could gain access to the users shell on the remote machine.

This problem has been fixed by the Security Team in version 2.0.6a-3.2
for the stable Debian GNU/Linux 2.2.

We recommend that you upgrade your gftp package.



Solution : http://www.debian.org/security/2001/dsa-084
Risk factor : High';

if (description) {
 script_id(14921);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "084");
 script_cve_id("CVE-1999-1562");
 script_bugtraq_id(3446);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA084] DSA-084-1 gftp");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-084-1 gftp");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gftp', release: '2.2', reference: '2.0.6a-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gftp is vulnerable in Debian 2.2.\nUpgrade to gftp_2.0.6a-3.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
