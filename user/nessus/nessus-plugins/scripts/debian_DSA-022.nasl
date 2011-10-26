# This script was automatically generated from the dsa-022
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = 'Former versions of the exmh program used /tmp for storing
temporary files. No checks were made to ensure that nobody placed a symlink
with the same name in /tmp in the meantime and thus was vulnerable to a symlink
attack. This could lead to a malicious local user being able to overwrite any
file writable by the user executing exmh. Upstream developers have reported and
fixed this. The exmh program now use /tmp/login unless TMPDIR or EXMHTMPDIR
is set. 

We recommend you upgrade your exmh packages immediately.


Solution : http://www.debian.org/security/2001/dsa-022
Risk factor : High';

if (description) {
 script_id(14859);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "022");
 script_cve_id("CVE-2001-0125");
 script_bugtraq_id(2327);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA022] DSA-022-1 exmh");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-022-1 exmh");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'exmh', release: '2.2', reference: '2.1.1-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package exmh is vulnerable in Debian 2.2.\nUpgrade to exmh_2.1.1-1.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
