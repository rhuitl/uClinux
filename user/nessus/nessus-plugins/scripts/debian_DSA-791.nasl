# This script was automatically generated from the dsa-791
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Max Vozeler discovered that the lockmail program from maildrop, a
simple mail delivery agent with filtering abilities, does not drop
group privileges before executing commands given on the commandline,
allowing an attacker to execute arbitrary commands with privileges of
the group mail.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 1.5.3-1.1sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 1.5.3-2.
We recommend that you upgrade your maildrop package.


Solution : http://www.debian.org/security/2005/dsa-791
Risk factor : High';

if (description) {
 script_id(19561);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "791");
 script_cve_id("CVE-2005-2655");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA791] DSA-791-1 maildrop");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-791-1 maildrop");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'maildrop', release: '', reference: '1.5.3-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package maildrop is vulnerable in Debian .\nUpgrade to maildrop_1.5.3-2\n');
}
if (deb_check(prefix: 'maildrop', release: '3.1', reference: '1.5.3-1.1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package maildrop is vulnerable in Debian 3.1.\nUpgrade to maildrop_1.5.3-1.1sarge1\n');
}
if (deb_check(prefix: 'maildrop', release: '3.1', reference: '1.5.3-1.1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package maildrop is vulnerable in Debian sarge.\nUpgrade to maildrop_1.5.3-1.1sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
