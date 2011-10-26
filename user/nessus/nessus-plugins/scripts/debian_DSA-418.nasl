# This script was automatically generated from the dsa-418
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A bug was discovered in vbox3, a voice response system for isdn4linux,
whereby root privileges were not properly relinquished before
executing a user-supplied tcl script.  By exploiting this
vulnerability, a local user could gain root privileges.
For the current stable distribution (woody) this problem has been
fixed in version 0.1.7.1.
For the unstable distribution, this problem has been fixed in version 0.1.8.
We recommend that you update your vbox3 package.


Solution : http://www.debian.org/security/2004/dsa-418
Risk factor : High';

if (description) {
 script_id(15255);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "418");
 script_cve_id("CVE-2004-0015");
 script_bugtraq_id(9381);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA418] DSA-418-1 vbox3");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-418-1 vbox3");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'vbox3', release: '3.0', reference: '0.1.7.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package vbox3 is vulnerable in Debian 3.0.\nUpgrade to vbox3_0.1.7.1\n');
}
if (deb_check(prefix: 'vbox3', release: '3.0', reference: '0.1.7.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package vbox3 is vulnerable in Debian woody.\nUpgrade to vbox3_0.1.7.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
