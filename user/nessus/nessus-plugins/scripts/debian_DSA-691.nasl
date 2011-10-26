# This script was automatically generated from the dsa-691
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several vulnerabilities have been discovered in abuse, the SDL port of
the Abuse action game.  The Common Vulnerabilities and Exposures
project identifies the following problems:
    Erik Sjölund discovered several buffer overflows in the command line
    handling, which could lead to the execution of arbitrary code with
    elevated privileges since it is installed setuid root.
    Steve Kemp discovered that abuse creates some files without
    dropping privileges first, which may lead to the creation and
    overwriting of arbitrary files.
For the stable distribution (woody) these problems have been fixed in
version 2.00+-3woody4.
The unstable distribution (sid) does not contain an abuse package anymore.
We recommend that you upgrade your abuse package.


Solution : http://www.debian.org/security/2005/dsa-691
Risk factor : High';

if (description) {
 script_id(17286);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "691");
 script_cve_id("CVE-2005-0098", "CVE-2005-0099");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA691] DSA-691-1 abuse");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-691-1 abuse");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'abuse', release: '3.0', reference: '2.00+-3woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package abuse is vulnerable in Debian 3.0.\nUpgrade to abuse_2.00+-3woody4\n');
}
if (deb_check(prefix: 'abuse', release: '3.0', reference: '2.00+-3woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package abuse is vulnerable in Debian woody.\nUpgrade to abuse_2.00+-3woody4\n');
}
if (w) { security_hole(port: 0, data: desc); }
