# This script was automatically generated from the dsa-521
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
jaguar@felinemenace.org discovered a format string vulnerability in
sup, a set of programs to synchronize collections of files across a
number of machines, whereby a remote attacker could potentially cause
arbitrary code to be executed with the privileges of the supfilesrv
process (this process does not run automatically by default).
CVE-2004-0451: format string vulnerabilities in sup via syslog(3) in
logquit, logerr, loginfo functions
For the current stable distribution (woody), this problem has been
fixed in version 1.8-8woody2.
For the unstable distribution (sid), this problem will be fixed soon.
We recommend that you update your sup package.


Solution : http://www.debian.org/security/2004/dsa-521
Risk factor : High';

if (description) {
 script_id(15358);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "521");
 script_cve_id("CVE-2004-0451");
 script_bugtraq_id(10571);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA521] DSA-521-1 sup");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-521-1 sup");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'sup', release: '3.0', reference: '1.8-8woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sup is vulnerable in Debian 3.0.\nUpgrade to sup_1.8-8woody2\n');
}
if (deb_check(prefix: 'sup', release: '3.0', reference: '1.8-8woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sup is vulnerable in Debian woody.\nUpgrade to sup_1.8-8woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
