# This script was automatically generated from the dsa-527
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Ulf Härnhammar discovered a vulnerability in pavuk, a file retrieval
program, whereby an oversized HTTP 305 response sent by a malicious
server could cause arbitrary code to be executed with the privileges
of the pavuk process.
For the current stable distribution (woody), this problem has been
fixed in version 0.9pl28-1woody1.
pavuk is no longer included in the unstable distribution of Debian.
We recommend that you update your pavuk package.


Solution : http://www.debian.org/security/2004/dsa-527
Risk factor : High';

if (description) {
 script_id(15364);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "527");
 script_cve_id("CVE-2004-0456");
 script_bugtraq_id(10633);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA527] DSA-527-1 pavuk");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-527-1 pavuk");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'pavuk', release: '3.0', reference: '0.9pl28-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pavuk is vulnerable in Debian 3.0.\nUpgrade to pavuk_0.9pl28-1woody1\n');
}
if (deb_check(prefix: 'pavuk', release: '3.0', reference: '0.9pl28-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pavuk is vulnerable in Debian woody.\nUpgrade to pavuk_0.9pl28-1woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
