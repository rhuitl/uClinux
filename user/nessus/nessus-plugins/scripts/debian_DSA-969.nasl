# This script was automatically generated from the dsa-969
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Max Vozeler discovered a vulnerability in scponly, a utility to
restrict user commands to scp and sftp, that could lead to the
execution of arbitray commands as root.  The system is only vulnerable
if the program scponlyc is installed setuid root and if regular users
have shell access to the machine.
The old stable distribution (woody) does not contain an scponly package.
For the stable distribution (sarge) this problem has been fixed in
version 4.0-1sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 4.6-1.
We recommend that you upgrade your scponly package.


Solution : http://www.debian.org/security/2006/dsa-969
Risk factor : High';

if (description) {
 script_id(22835);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "969");
 script_cve_id("CVE-2005-4532", "CVE-2005-4533");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA969] DSA-969-1 scponly");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-969-1 scponly");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'scponly', release: '', reference: '4.6-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package scponly is vulnerable in Debian .\nUpgrade to scponly_4.6-1\n');
}
if (deb_check(prefix: 'scponly', release: '3.1', reference: '4.0-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package scponly is vulnerable in Debian 3.1.\nUpgrade to scponly_4.0-1sarge1\n');
}
if (deb_check(prefix: 'scponly', release: '3.1', reference: '4.0-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package scponly is vulnerable in Debian sarge.\nUpgrade to scponly_4.0-1sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
