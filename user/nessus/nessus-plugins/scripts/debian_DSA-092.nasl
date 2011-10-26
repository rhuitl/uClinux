# This script was automatically generated from the dsa-092
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Nicolas Boullis found a nasty security problem in the wmtv (a
dockable video4linux TV player for windowmaker) package as
distributed in Debian GNU/Linux 2.2.

wmtv can optionally run a command if you double-click on the TV
window. This command can be specified using the -e command line
option. However, since wmtv is installed suid root, this command
was also run as root, which gives local users a very simple way
to get root access.

This has been fixed in version 0.6.5-2potato1 by dropping root
privileges before executing the command. We recommend that you
upgrade your wmtv package immediately.



Solution : http://www.debian.org/security/2001/dsa-092
Risk factor : High';

if (description) {
 script_id(14929);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "092");
 script_cve_id("CVE-2001-1272");
 script_bugtraq_id(3658);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA092] DSA-092-1 wmtv");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-092-1 wmtv");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'wmtv', release: '2.2', reference: '0.6.5-2potato1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package wmtv is vulnerable in Debian 2.2.\nUpgrade to wmtv_0.6.5-2potato1\n');
}
if (w) { security_hole(port: 0, data: desc); }
