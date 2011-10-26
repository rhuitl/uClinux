# This script was automatically generated from the dsa-513
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
jaguar@felinemenace.org discovered a format string vulnerability in
log2mail, whereby a user able to log a specially crafted message to a
logfile monitored by log2mail (for example, via syslog) could cause
arbitrary code to be executed with the privileges of the log2mail
process.  By default, this process runs as user \'log2mail\', which is a
member of group \'adm\' (which has access to read system logfiles).
CVE-2004-0450: log2mail format string vulnerability via syslog(3) in
printlog()
For the current stable distribution (woody), this problem has been
fixed in version 0.2.5.2.
For the unstable distribution (sid), this problem will be fixed soon.
We recommend that you update your log2mail package.


Solution : http://www.debian.org/security/2004/dsa-513
Risk factor : High';

if (description) {
 script_id(15350);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "513");
 script_cve_id("CVE-2004-0450");
 script_bugtraq_id(10460);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA513] DSA-513-1 log2mail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-513-1 log2mail");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'log2mail', release: '3.0', reference: '0.2.5.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package log2mail is vulnerable in Debian 3.0.\nUpgrade to log2mail_0.2.5.2\n');
}
if (deb_check(prefix: 'log2mail', release: '3.0', reference: '0.2.5.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package log2mail is vulnerable in Debian woody.\nUpgrade to log2mail_0.2.5.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
