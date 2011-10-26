# This script was automatically generated from the dsa-078
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Byrial Jensen found a nasty problem in slrn (a threaded news reader).
The notice on slrn-announce describes it as follows:



    When trying to decode binaries, the built-in code executes any shell
    scripts the article might contain, apparently assuming they would be
    some kind of self-extracting archive.

This problem has been fixed in version 0.9.6.2-9potato2 by removing
this feature. 



Solution : http://www.debian.org/security/2001/dsa-078
Risk factor : High';

if (description) {
 script_id(14915);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "078");
 script_cve_id("CVE-2001-1035");
 script_bugtraq_id(3364);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA078] DSA-078-1 slrn");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-078-1 slrn");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'slrn', release: '2.2', reference: '0.9.6.2-9potato2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package slrn is vulnerable in Debian 2.2.\nUpgrade to slrn_0.9.6.2-9potato2\n');
}
if (deb_check(prefix: 'slrnpull', release: '2.2', reference: '0.9.6.2-9potato2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package slrnpull is vulnerable in Debian 2.2.\nUpgrade to slrnpull_0.9.6.2-9potato2\n');
}
if (w) { security_hole(port: 0, data: desc); }
