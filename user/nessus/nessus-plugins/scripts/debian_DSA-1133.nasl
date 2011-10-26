# This script was automatically generated from the dsa-1133
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several remote vulnerabilities have been discovered in the Mantis bug
tracking system, which may lead to the execution of arbitrary web script.
The Common Vulnerabilities and Exposures project identifies the following
problems:
    A cross-site scripting vulnerability was discovered in
    config_defaults_inc.php.
    Cross-site scripting vulnerabilities were discovered in query_store.php
    and manage_proj_create.php.
    Multiple cross-site scripting vulnerabilities were discovered in
    view_all_set.php, manage_user_page.php, view_filters_page.php and
    proj_doc_delete.php.
    Multiple cross-site scripting vulnerabilities were discovered in
    view_all_set.php.
For the stable distribution (sarge) these problems have been fixed in
version 0.19.2-5sarge4.1.
For the unstable distribution (sid) these problems have been fixed in
version 0.19.4-3.1.
We recommend that you upgrade your mantis package.


Solution : http://www.debian.org/security/2006/dsa-1133
Risk factor : High';

if (description) {
 script_id(22675);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1133");
 script_cve_id("CVE-2006-0664", "CVE-2006-0665", "CVE-2006-0841", "CVE-2006-1577");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1133] DSA-1133-1 mantis");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1133-1 mantis");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mantis', release: '', reference: '0.19.4-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mantis is vulnerable in Debian .\nUpgrade to mantis_0.19.4-3.1\n');
}
if (deb_check(prefix: 'mantis', release: '3.1', reference: '0.19.2-5sarge4.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mantis is vulnerable in Debian 3.1.\nUpgrade to mantis_0.19.2-5sarge4.1\n');
}
if (deb_check(prefix: 'mantis', release: '3.1', reference: '0.19.2-5sarge4.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mantis is vulnerable in Debian sarge.\nUpgrade to mantis_0.19.2-5sarge4.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
