# This script was automatically generated from the dsa-410
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A vulnerability was discovered in libnids, a library used to analyze
IP network traffic, whereby a carefully crafted TCP datagram could
cause memory corruption and potentially execute arbitrary code with
the privileges of the user executing a program which uses libnids
(such as dsniff).
For the current stable distribution (woody) this problem has been
fixed in version 1.16-3woody1.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you update your libnids package.


Solution : http://www.debian.org/security/2004/dsa-410
Risk factor : High';

if (description) {
 script_id(15247);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "410");
 script_cve_id("CVE-2003-0850");
 script_bugtraq_id(8905);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA410] DSA-410-1 libnids");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-410-1 libnids");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libnids-dev', release: '3.0', reference: '1.16-3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnids-dev is vulnerable in Debian 3.0.\nUpgrade to libnids-dev_1.16-3woody1\n');
}
if (deb_check(prefix: 'libnids1', release: '3.0', reference: '1.16-3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnids1 is vulnerable in Debian 3.0.\nUpgrade to libnids1_1.16-3woody1\n');
}
if (deb_check(prefix: 'libnids', release: '3.0', reference: '1.16-3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnids is vulnerable in Debian woody.\nUpgrade to libnids_1.16-3woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
