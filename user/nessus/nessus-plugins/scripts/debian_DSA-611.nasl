# This script was automatically generated from the dsa-611
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
"infamous41md" discovered a buffer overflow in htget, a file grabber
that will get files from HTTP servers.  It is possible to overflow a
buffer and execute arbitrary code by accessing a malicious URL.
For the stable distribution (woody) this problem has been fixed in
version 0.93-1.1woody1.
This package is not present in the testing and unstable distributions.
We recommend that you upgrade your htget package.


Solution : http://www.debian.org/security/2004/dsa-611
Risk factor : High';

if (description) {
 script_id(16007);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "611");
 script_cve_id("CVE-2004-0852");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA611] DSA-611-1 htget");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-611-1 htget");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'htget', release: '3.0', reference: '0.93-1.1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package htget is vulnerable in Debian 3.0.\nUpgrade to htget_0.93-1.1woody1\n');
}
if (deb_check(prefix: 'htget', release: '3.0', reference: '0.93-1.1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package htget is vulnerable in Debian woody.\nUpgrade to htget_0.93-1.1woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
