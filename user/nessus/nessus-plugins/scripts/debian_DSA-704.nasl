# This script was automatically generated from the dsa-704
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Jens Steube discovered several vulnerabilities in remstats, the remote
statistics system.  The Common Vulnerabilities and Exposures project
identifies the following problems:
    When processing uptime data on the unix-server a temporary file is
    opened in an insecure fashion which could be used for a symlink
    attack to create or overwrite arbitrary files with the permissions
    of the remstats user.
    The remoteping service can be exploited to execute arbitrary
    commands due to missing input sanitising.
For the stable distribution (woody) these problems have been fixed in
version 1.00a4-8woody1.
For the unstable distribution (sid) these problems have been fixed in
version 1.0.13a-5.
We recommend that you upgrade your remstats packages.


Solution : http://www.debian.org/security/2005/dsa-704
Risk factor : High';

if (description) {
 script_id(18009);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "704");
 script_cve_id("CVE-2005-0387", "CVE-2005-0388");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA704] DSA-704-1 remstats");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-704-1 remstats");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'remstats', release: '3.0', reference: '1.00a4-8woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package remstats is vulnerable in Debian 3.0.\nUpgrade to remstats_1.00a4-8woody1\n');
}
if (deb_check(prefix: 'remstats-bintools', release: '3.0', reference: '1.00a4-8woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package remstats-bintools is vulnerable in Debian 3.0.\nUpgrade to remstats-bintools_1.00a4-8woody1\n');
}
if (deb_check(prefix: 'remstats-doc', release: '3.0', reference: '1.00a4-8woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package remstats-doc is vulnerable in Debian 3.0.\nUpgrade to remstats-doc_1.00a4-8woody1\n');
}
if (deb_check(prefix: 'remstats-servers', release: '3.0', reference: '1.00a4-8woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package remstats-servers is vulnerable in Debian 3.0.\nUpgrade to remstats-servers_1.00a4-8woody1\n');
}
if (deb_check(prefix: 'remstats', release: '3.1', reference: '1.0.13a-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package remstats is vulnerable in Debian 3.1.\nUpgrade to remstats_1.0.13a-5\n');
}
if (deb_check(prefix: 'remstats', release: '3.0', reference: '1.00a4-8woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package remstats is vulnerable in Debian woody.\nUpgrade to remstats_1.00a4-8woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
