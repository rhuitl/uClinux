# This script was automatically generated from the dsa-485
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Max Vozeler discovered two format string vulnerabilities in ssmtp, a
simple mail transport agent.  Untrusted values in the functions die()
and log_event() were passed to printf-like functions as format
strings.  These vulnerabilities could potentially be exploited by a
remote mail relay to gain the privileges of the ssmtp process
(including potentially root).
For the current stable distribution (woody) this problem will be fixed
in version 2.50.6.1.
For the unstable distribution (sid), this problem will be fixed soon.
We recommend that you update your ssmtp package.


Solution : http://www.debian.org/security/2004/dsa-485
Risk factor : High';

if (description) {
 script_id(15322);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "485");
 script_cve_id("CVE-2004-0156");
 script_bugtraq_id(10150);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA485] DSA-485-1 ssmtp");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-485-1 ssmtp");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'ssmtp', release: '3.0', reference: '2.50.6.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ssmtp is vulnerable in Debian 3.0.\nUpgrade to ssmtp_2.50.6.1\n');
}
if (deb_check(prefix: 'ssmtp', release: '3.0', reference: '2.50.6.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ssmtp is vulnerable in Debian woody.\nUpgrade to ssmtp_2.50.6.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
