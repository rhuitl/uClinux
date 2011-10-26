# This script was automatically generated from the dsa-352
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
fdclone creates a temporary directory in /tmp as a workspace.
However, if this directory already exists, the existing directory is
used instead, regardless of its ownership or permissions.  This would
allow an attacker to gain access to fdclone\'s temporary files and
their contents, or replace them with other files under the attacker\'s
control.
For the stable distribution (woody) this problem has been fixed in
version 2.00a-1woody3.
For the unstable distribution (sid) this problem has been fixed in
version 2.04-1.
We recommend that you update your fdclone package.


Solution : http://www.debian.org/security/2003/dsa-352
Risk factor : High';

if (description) {
 script_id(15189);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "352");
 script_cve_id("CVE-2003-0596");
 script_bugtraq_id(8247);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA352] DSA-352-1 fdclone");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-352-1 fdclone");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'fdclone', release: '3.0', reference: '2.00a-1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fdclone is vulnerable in Debian 3.0.\nUpgrade to fdclone_2.00a-1woody3\n');
}
if (deb_check(prefix: 'fdclone', release: '3.1', reference: '2.04-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fdclone is vulnerable in Debian 3.1.\nUpgrade to fdclone_2.04-1\n');
}
if (deb_check(prefix: 'fdclone', release: '3.0', reference: '2.00a-1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fdclone is vulnerable in Debian woody.\nUpgrade to fdclone_2.00a-1woody3\n');
}
if (w) { security_hole(port: 0, data: desc); }
