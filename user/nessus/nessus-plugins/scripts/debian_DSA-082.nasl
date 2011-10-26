# This script was automatically generated from the dsa-082
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Christophe Bailleux reported on bugtraq that Xvt is vulnerable to a
buffer overflow in its argument handling.  Since Xvt is installed
setuid root, it was possible for a normal user to pass
carefully-crafted arguments to xvt so that xvt executed a root shell.

This problem has been fixed by the maintainer in version 2.1-13 of xvt
for Debian unstable and 2.1-13.0potato.1 for the stable Debian
GNU/Linux 2.2.

We recommend that you upgrade your xvt package immediately.



Solution : http://www.debian.org/security/2001/dsa-082
Risk factor : High';

if (description) {
 script_id(14919);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "082");
 script_bugtraq_id(2964);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA082] DSA-082-1 xvt");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-082-1 xvt");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'xvt', release: '2.2', reference: '2.1-13.0potato.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xvt is vulnerable in Debian 2.2.\nUpgrade to xvt_2.1-13.0potato.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
