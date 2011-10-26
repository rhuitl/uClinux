# This script was automatically generated from the dsa-062
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Samuel Dralet reported on bugtraq that version 2.6.2 of rxvt (a
VT102 terminal emulator for X) have a buffer overflow in the
tt_printf() function. A local user could abuse this making rxvt
print a special string using that function, for example by using
the -T or -name command-line options.
That string would cause a
stack overflow and contain code which rxvt will execute.

Since rxvt is installed sgid utmp an attacker could use this
to gain utmp which would allow them to modify the utmp file.

This has been fixed in version 2.6.2-2.1, and we recommend that
you upgrade your rxvt package.



Solution : http://www.debian.org/security/2001/dsa-062
Risk factor : High';

if (description) {
 script_id(14899);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "062");
 script_cve_id("CVE-2001-1077");
 script_bugtraq_id(2878);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA062] DSA-062-1 rxvt");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-062-1 rxvt");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'rxvt', release: '2.2', reference: '2.6.2-2.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package rxvt is vulnerable in Debian 2.2.\nUpgrade to rxvt_2.6.2-2.1\n');
}
if (deb_check(prefix: 'rxvt-ml', release: '2.2', reference: '2.6.2-2.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package rxvt-ml is vulnerable in Debian 2.2.\nUpgrade to rxvt-ml_2.6.2-2.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
