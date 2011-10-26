# This script was automatically generated from the dsa-374
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
libpam-smb is a PAM authentication module which makes it possible to
authenticate users against a password database managed by Samba or a
Microsoft Windows server.  If a long password is supplied, this can
cause a buffer overflow which could be exploited to execute arbitrary
code with the privileges of the process which invokes PAM services.
For the stable distribution (woody) this problem has been fixed in
version 1.1.6-1.1woody1.
The unstable distribution (sid) does not contain a libpam-smb
package.
We recommend that you update your libpam-smb package.


Solution : http://www.debian.org/security/2003/dsa-374
Risk factor : High';

if (description) {
 script_id(15211);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "374");
 script_cve_id("CVE-2003-0686");
 script_bugtraq_id(8491);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA374] DSA-374-1 libpam-smb");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-374-1 libpam-smb");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libpam-smb', release: '3.0', reference: '1.1.6-1.1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpam-smb is vulnerable in Debian 3.0.\nUpgrade to libpam-smb_1.1.6-1.1woody1\n');
}
if (deb_check(prefix: 'libpam-smb', release: '3.0', reference: '1.1.6-1.1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpam-smb is vulnerable in Debian woody.\nUpgrade to libpam-smb_1.1.6-1.1woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
