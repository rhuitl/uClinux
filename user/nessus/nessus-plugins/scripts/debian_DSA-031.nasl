# This script was automatically generated from the dsa-031
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = 'Todd Miller announced a new version of sudo which corrects
a buffer overflow that could potentially be used to gain root privileges on the
local system. The fix from sudo 1.6.3p6 is available in sudo 1.6.2p2-1potato1
for Debian 2.2 (potato).  


Solution : http://www.debian.org/security/2001/dsa-031
Risk factor : High';

if (description) {
 script_id(14868);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "031");
 script_cve_id("CVE-2001-0279");
 script_bugtraq_id(2829);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA031] DSA-031-2 sudo");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-031-2 sudo");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'sudo', release: '2.2', reference: '1.6.2p2-1potato1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sudo is vulnerable in Debian 2.2.\nUpgrade to sudo_1.6.2p2-1potato1\n');
}
if (w) { security_hole(port: 0, data: desc); }
