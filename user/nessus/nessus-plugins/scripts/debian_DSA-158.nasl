# This script was automatically generated from the dsa-158
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The developers of Gaim, an instant messenger client that combines
several different networks, found a vulnerability in the hyperlink
handling code.  The \'Manual\' browser command passes an untrusted
string to the shell without escaping or reliable quoting, permitting
an attacker to execute arbitrary commands on the users machine.
Unfortunately, Gaim doesn\'t display the hyperlink before the user
clicks on it.  Users who use other inbuilt browser commands aren\'t
vulnerable.
This problem has been fixed in version 0.58-2.2 for the current
stable distribution (woody) and in version 0.59.1-2 for the unstable
distribution (sid).  The old stable distribution (potato) is not
affected since it doesn\'t ship the Gaim program.
The fixed version of Gaim no longer passes the user\'s manual browser
command to the shell.  Commands which contain the %s in quotes will
need to be amended, so they don\'t contain any quotes.  The \'Manual\'
browser command can be edited in the \'General\' pane of the
\'Preferences\' dialog, which can be accessed by clicking \'Options\' from
the login window, or \'Tools\' and then \'Preferences\' from the menu bar
in the buddy list window.
We recommend that you upgrade your gaim package immediately.


Solution : http://www.debian.org/security/2002/dsa-158
Risk factor : High';

if (description) {
 script_id(14995);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "158");
 script_cve_id("CVE-2002-0989");
 script_bugtraq_id(5574);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA158] DSA-158-1 gaim");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-158-1 gaim");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gaim', release: '3.0', reference: '0.58-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gaim is vulnerable in Debian 3.0.\nUpgrade to gaim_0.58-2.2\n');
}
if (deb_check(prefix: 'gaim-common', release: '3.0', reference: '0.58-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gaim-common is vulnerable in Debian 3.0.\nUpgrade to gaim-common_0.58-2.2\n');
}
if (deb_check(prefix: 'gaim-gnome', release: '3.0', reference: '0.58-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gaim-gnome is vulnerable in Debian 3.0.\nUpgrade to gaim-gnome_0.58-2.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
