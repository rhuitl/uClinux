# This script was automatically generated from the dsa-835
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Javier Fernández-Sanguino Peña discovered several insecure temporary
file uses in cfengine, a tool for configuring and maintaining
networked machines, that can be exploited by a symlink attack to
overwrite arbitrary files owned by the user executing cfengine, which
is probably root.
For the old stable distribution (woody) these problems have been fixed in
version 1.6.3-9woody1.
For the stable distribution (sarge) these problems have been fixed in
version 1.6.5-1sarge1.
For the unstable distribution (sid) these problems will be fixed soon.
We recommend that you upgrade your cfengine package.


Solution : http://www.debian.org/security/2005/dsa-835
Risk factor : High';

if (description) {
 script_id(19804);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "835");
 script_cve_id("CVE-2005-2960", "CVE-2005-3137");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA835] DSA-835-1 cfengine");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-835-1 cfengine");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'cfengine', release: '3.0', reference: '1.6.3-9woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cfengine is vulnerable in Debian 3.0.\nUpgrade to cfengine_1.6.3-9woody1\n');
}
if (deb_check(prefix: 'cfengine-doc', release: '3.0', reference: '1.6.3-9woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cfengine-doc is vulnerable in Debian 3.0.\nUpgrade to cfengine-doc_1.6.3-9woody1\n');
}
if (deb_check(prefix: 'cfengine', release: '3.1', reference: '1.6.5-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cfengine is vulnerable in Debian 3.1.\nUpgrade to cfengine_1.6.5-1sarge1\n');
}
if (deb_check(prefix: 'cfengine-doc', release: '3.1', reference: '1.6.5-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cfengine-doc is vulnerable in Debian 3.1.\nUpgrade to cfengine-doc_1.6.5-1sarge1\n');
}
if (deb_check(prefix: 'cfengine', release: '3.1', reference: '1.6.5-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cfengine is vulnerable in Debian sarge.\nUpgrade to cfengine_1.6.5-1sarge1\n');
}
if (deb_check(prefix: 'cfengine', release: '3.0', reference: '1.6.3-9woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cfengine is vulnerable in Debian woody.\nUpgrade to cfengine_1.6.3-9woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
