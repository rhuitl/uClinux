# This script was automatically generated from the dsa-687
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Ulf Härnhammar from the Debian Security Audit Project discovered a
format string vulnerability in bidwatcher, a tool for watching and
bidding on eBay auctions.  This problem can be triggered remotely by a
web server of eBay, or someone pretending to be eBay, sending certain
data back.  As of version 1.3.17 the program uses cURL and is not
vulnerable anymore.
For the stable distribution (woody) this problem has been fixed in
version 1.3.3-1woody1.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you upgrade your bidwatcher package.


Solution : http://www.debian.org/security/2005/dsa-687
Risk factor : High';

if (description) {
 script_id(17143);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "687");
 script_cve_id("CVE-2005-0158");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA687] DSA-687-1 bidwatcher");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-687-1 bidwatcher");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'bidwatcher', release: '3.0', reference: '1.3.3-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bidwatcher is vulnerable in Debian 3.0.\nUpgrade to bidwatcher_1.3.3-1woody1\n');
}
if (deb_check(prefix: 'bidwatcher', release: '3.0', reference: '1.3.3-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bidwatcher is vulnerable in Debian woody.\nUpgrade to bidwatcher_1.3.3-1woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
