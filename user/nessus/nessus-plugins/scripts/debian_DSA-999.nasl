# This script was automatically generated from the dsa-999
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several security related problems have been discovered in lurker, an
archive tool for mailing lists with integrated search engine.  The
Common Vulnerability and Exposures project identifies the following
problems:
    Lurker\'s mechanism for specifying configuration files was
    vulnerable to being overridden.  As lurker includes sections of
    unparsed config files in its output, an attacker could manipulate
    lurker into reading any file readable by the www-data user.
    It is possible for a remote attacker to create or overwrite files
    in any writable directory that is named "mbox".
    Missing input sanitising allows an attacker to inject arbitrary
    web script or HTML.
The old stable distribution (woody) does not contain lurker packages.
For the stable distribution (sarge) these problems have been fixed in
version 1.2-5sarge1.
For the unstable distribution (sid) these problems have been fixed in
version 2.1-1.
We recommend that you upgrade your lurker package.


Solution : http://www.debian.org/security/2006/dsa-999
Risk factor : High';

if (description) {
 script_id(22865);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "999");
 script_cve_id("CVE-2006-1062", "CVE-2006-1063", "CVE-2006-1064");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA999] DSA-999-1 lurker");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-999-1 lurker");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'lurker', release: '', reference: '2.1-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lurker is vulnerable in Debian .\nUpgrade to lurker_2.1-1\n');
}
if (deb_check(prefix: 'lurker', release: '3.1', reference: '1.2-5sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lurker is vulnerable in Debian 3.1.\nUpgrade to lurker_1.2-5sarge1\n');
}
if (deb_check(prefix: 'lurker', release: '3.1', reference: '1.2-5sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lurker is vulnerable in Debian sarge.\nUpgrade to lurker_1.2-5sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
