# This script was automatically generated from the dsa-290
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Michal Zalewski discovered a buffer overflow, triggered by a char to
int conversion, in the address parsing code in sendmail, a widely used
powerful, efficient, and scalable mail transport agent.  This problem
is potentially remotely exploitable.
For the stable distribution (woody) this problem has been fixed in
version 8.12.3+3.5Wbeta-5.4
For the old stable distribution (potato) this problem has been
fixed in version 8.9.3+3.2W-25
For the unstable distribution (sid) this problem has been
fixed in version 8.12.9+3.5Wbeta-1
We recommend that you upgrade your sendmail-wide packages.


Solution : http://www.debian.org/security/2003/dsa-290
Risk factor : High';

if (description) {
 script_id(15127);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-b-0003");
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "290");
 script_cve_id("CVE-2003-0161");
 script_bugtraq_id(7230);
 script_xref(name: "CERT", value: "897604");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA290] DSA-290-1 sendmail-wide");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-290-1 sendmail-wide");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'sendmail-wide', release: '2.2', reference: '8.9.3+3.2W-25')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sendmail-wide is vulnerable in Debian 2.2.\nUpgrade to sendmail-wide_8.9.3+3.2W-25\n');
}
if (deb_check(prefix: 'sendmail-wide', release: '3.0', reference: '8.12.3+3.5Wbeta-5.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sendmail-wide is vulnerable in Debian 3.0.\nUpgrade to sendmail-wide_8.12.3+3.5Wbeta-5.4\n');
}
if (deb_check(prefix: 'sendmail-wide', release: '3.1', reference: '8.12.9+3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sendmail-wide is vulnerable in Debian 3.1.\nUpgrade to sendmail-wide_8.12.9+3\n');
}
if (deb_check(prefix: 'sendmail-wide', release: '2.2', reference: '8.9.3+3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sendmail-wide is vulnerable in Debian potato.\nUpgrade to sendmail-wide_8.9.3+3\n');
}
if (deb_check(prefix: 'sendmail-wide', release: '3.0', reference: '8.12.3+3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sendmail-wide is vulnerable in Debian woody.\nUpgrade to sendmail-wide_8.12.3+3\n');
}
if (w) { security_hole(port: 0, data: desc); }
