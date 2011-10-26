# This script was automatically generated from the dsa-827
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Moritz Muehlenhoff discovered the handler code for backupninja creates
a temporary file with a predictable filename, leaving it vulnerable to
a symlink attack. 
The old stable distribution (woody) does not contain the backupninja package.
For the stable distribution (sarge) this problem has been fixed in
version 0.5-3sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 0.8-2.
We recommend that you upgrade your backupninja package.


Solution : http://www.debian.org/security/2005/dsa-827
Risk factor : High';

if (description) {
 script_id(19796);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "827");
 script_cve_id("CVE-2005-3111");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA827] DSA-827-1 backupninja");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-827-1 backupninja");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'backupninja', release: '', reference: '0.8-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package backupninja is vulnerable in Debian .\nUpgrade to backupninja_0.8-2\n');
}
if (deb_check(prefix: 'backupninja', release: '3.1', reference: '0.5-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package backupninja is vulnerable in Debian 3.1.\nUpgrade to backupninja_0.5-3sarge1\n');
}
if (deb_check(prefix: 'backupninja', release: '3.1', reference: '0.5-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package backupninja is vulnerable in Debian sarge.\nUpgrade to backupninja_0.5-3sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
