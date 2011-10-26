# This script was automatically generated from the dsa-021
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = 'WireX have found some occurrences of insecure opening of
temporary files in htdigest and htpasswd. Both programs are not installed
setuid or setgid and thus the impact should be minimal. The Apache group has
released another security bugfix which fixes a vulnerability in mod_rewrite
which may result the remote attacker to access arbitrary files on the web
server.


Solution : http://www.debian.org/security/2001/dsa-021
Risk factor : High';

if (description) {
 script_id(14858);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "021");
 script_cve_id("CVE-2001-0131");
 script_bugtraq_id(2182);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA021] DSA-021-1 apache");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-021-1 apache");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'apache', release: '2.2', reference: '1.3.9-13.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache is vulnerable in Debian 2.2.\nUpgrade to apache_1.3.9-13.2\n');
}
if (deb_check(prefix: 'apache-common', release: '2.2', reference: '1.3.9-13.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache-common is vulnerable in Debian 2.2.\nUpgrade to apache-common_1.3.9-13.2\n');
}
if (deb_check(prefix: 'apache-dev', release: '2.2', reference: '1.3.9-13.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache-dev is vulnerable in Debian 2.2.\nUpgrade to apache-dev_1.3.9-13.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
