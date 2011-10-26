# This script was automatically generated from the dsa-760
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several vulnerabilities have been discovered in ekg, a console Gadu
Gadu client, an instant messaging program.  The Common Vulnerabilities
and Exposures project identifies the following vulnerabilities:
    Marcin Owsiany and Wojtek Kaniewski discovered insecure temporary
    file creation in contributed scripts.
    Marcin Owsiany and Wojtek Kaniewski discovered potential shell
    command injection in a contributed script.
    Eric Romang discovered insecure temporary file creation and
    arbitrary command execution in a contributed script that can be
    exploited by a local attacker.
The old stable distribution (woody) does not contain an ekg package.
For the stable distribution (sarge) these problems have been fixed in
version 1.5+20050411-4.
For the unstable distribution (sid) these problems have been fixed in
version 1.5+20050712+1.6rc2-1.
We recommend that you upgrade your ekg package.


Solution : http://www.debian.org/security/2005/dsa-760
Risk factor : High';

if (description) {
 script_id(19223);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "760");
 script_cve_id("CVE-2005-1850", "CVE-2005-1851", "CVE-2005-1916");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA760] DSA-760-1 ekg");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-760-1 ekg");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'ekg', release: '', reference: '1.5+20050712+1.6rc2-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ekg is vulnerable in Debian .\nUpgrade to ekg_1.5+20050712+1.6rc2-1\n');
}
if (deb_check(prefix: 'ekg', release: '3.1', reference: '1.5+20050411-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ekg is vulnerable in Debian 3.1.\nUpgrade to ekg_1.5+20050411-4\n');
}
if (deb_check(prefix: 'libgadu-dev', release: '3.1', reference: '1.5+20050411-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgadu-dev is vulnerable in Debian 3.1.\nUpgrade to libgadu-dev_1.5+20050411-4\n');
}
if (deb_check(prefix: 'libgadu3', release: '3.1', reference: '1.5+20050411-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgadu3 is vulnerable in Debian 3.1.\nUpgrade to libgadu3_1.5+20050411-4\n');
}
if (deb_check(prefix: 'ekg', release: '3.1', reference: '1.5+20050411-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ekg is vulnerable in Debian sarge.\nUpgrade to ekg_1.5+20050411-4\n');
}
if (w) { security_hole(port: 0, data: desc); }
