# This script was automatically generated from the dsa-720
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Jeroen van Wolffelaar noticed that the confirm add-on of SmartList,
the listmanager used on lists.debian.org, which is used on that host
as well, could be tricked to subscribe arbitrary addresses to the
lists.
For the stable distribution (woody) this problem has been fixed in
version 3.15-5.woody.1.
For the unstable distribution (sid) this problem has been fixed in
version 3.15-18.
We recommend that you upgrade your smartlist package.


Solution : http://www.debian.org/security/2005/dsa-720
Risk factor : High';

if (description) {
 script_id(18195);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "720");
 script_cve_id("CVE-2005-0157");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA720] DSA-720-1 smartlist");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-720-1 smartlist");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'smartlist', release: '3.0', reference: '3.15-5.woody.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package smartlist is vulnerable in Debian 3.0.\nUpgrade to smartlist_3.15-5.woody.1\n');
}
if (deb_check(prefix: 'smartlist', release: '3.1', reference: '3.15-18')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package smartlist is vulnerable in Debian 3.1.\nUpgrade to smartlist_3.15-18\n');
}
if (deb_check(prefix: 'smartlist', release: '3.0', reference: '3.15-5.woody.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package smartlist is vulnerable in Debian woody.\nUpgrade to smartlist_3.15-5.woody.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
