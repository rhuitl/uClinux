# This script was automatically generated from the dsa-048
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Marcus Meissner discovered that samba was not creating temporary
files safely in two places:


when a remote user queried a printer queue samba would create a
    temporary file in which the queue data would be written. This was being
    done using a predictable filename, and insecurely, allowing a local
    attacker to trick samba into overwriting arbitrary files.
smbclient "more" and "mput" commands also created temporary files
    in /tmp insecurely.


Both problems have been fixed in version 2.0.7-3.2, and we recommend
that you upgrade your samba package immediately. (This problem is also fixed
in the Samba 2.2 codebase.)

Note: DSA-048-1 included an incorrectly compiled sparc package, which
the second edition fixed.

The third edition of the advisory was made because Marc Jacobsen from HP
discovered that the security fixes from samba 2.0.8 did not fully fix the
/tmp symlink attack problem. The samba team released version 2.0.9 to fix
that, and those fixes have been added to version 2.0.7-3.3 of the Debian
samba packages.



Solution : http://www.debian.org/security/2001/dsa-048
Risk factor : High';

if (description) {
 script_id(14885);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "048");
 script_cve_id("CVE-2001-0406");
 script_bugtraq_id(2617);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA048] DSA-048-3 samba");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-048-3 samba");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'samba', release: '2.2', reference: '2.0.7-3.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package samba is vulnerable in Debian 2.2.\nUpgrade to samba_2.0.7-3.3\n');
}
if (deb_check(prefix: 'samba-common', release: '2.2', reference: '2.0.7-3.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package samba-common is vulnerable in Debian 2.2.\nUpgrade to samba-common_2.0.7-3.3\n');
}
if (deb_check(prefix: 'samba-doc', release: '2.2', reference: '2.0.7-3.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package samba-doc is vulnerable in Debian 2.2.\nUpgrade to samba-doc_2.0.7-3.3\n');
}
if (deb_check(prefix: 'smbclient', release: '2.2', reference: '2.0.7-3.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package smbclient is vulnerable in Debian 2.2.\nUpgrade to smbclient_2.0.7-3.3\n');
}
if (deb_check(prefix: 'smbfs', release: '2.2', reference: '2.0.7-3.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package smbfs is vulnerable in Debian 2.2.\nUpgrade to smbfs_2.0.7-3.3\n');
}
if (deb_check(prefix: 'swat', release: '2.2', reference: '2.0.7-3.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package swat is vulnerable in Debian 2.2.\nUpgrade to swat_2.0.7-3.3\n');
}
if (w) { security_hole(port: 0, data: desc); }
