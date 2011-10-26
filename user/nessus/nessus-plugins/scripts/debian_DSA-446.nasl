# This script was automatically generated from the dsa-446
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Ulf Härnhammar from the Debian Security Audit Project
discovered a vulnerability in
synaesthesia, a program which represents sounds visually.
synaesthesia created its configuration file while holding root
privileges, allowing a local user to create files owned by root and
writable by the user\'s primary group.  This type of vulnerability can
usually be easily exploited to execute arbitrary code with root
privileges by various means.
For the current stable distribution (woody) this problem has been
fixed in version 2.1-2.1woody1.
The unstable distribution (sid) is not affected by this problem, because
synaesthesia is no longer setuid.
We recommend that you update your synaesthesia package.


Solution : http://www.debian.org/security/2004/dsa-446
Risk factor : High';

if (description) {
 script_id(15283);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "446");
 script_cve_id("CVE-2004-0160");
 script_bugtraq_id(9713);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA446] DSA-446-1 synaesthesia");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-446-1 synaesthesia");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'synaesthesia', release: '3.0', reference: '2.1-2.1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package synaesthesia is vulnerable in Debian 3.0.\nUpgrade to synaesthesia_2.1-2.1woody1\n');
}
if (deb_check(prefix: 'synaesthesia', release: '3.0', reference: '2.1-2.1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package synaesthesia is vulnerable in Debian woody.\nUpgrade to synaesthesia_2.1-2.1woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
