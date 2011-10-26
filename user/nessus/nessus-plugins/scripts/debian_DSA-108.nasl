# This script was automatically generated from the dsa-108
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Nicolas Boullis found some security problems in the wmtv package (a
dockable video4linux TV player for windowmaker) which is distributed
in Debian GNU/Linux 2.2.  With the current version of wmtv, the
configuration file is written back as the superuser, and without any
further checks.  A malicious user might use that to damage important
files.
This problem has been fixed in version 0.6.5-2potato2 for the stable
distribution by dropping privileges as soon as possible and only
regaining them where required.  In the current testing/unstable
distribution this problem has been fixed in version 0.6.5-9 and above
by not requiring privileges anymore.  Both contain fixes for two
potential buffer overflows as well.
We recommend that you upgrade your wmtv packages immediately.


Solution : http://www.debian.org/security/2002/dsa-108
Risk factor : High';

if (description) {
 script_id(14945);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "108");
 script_cve_id("CVE-2002-0247", "CVE-2002-0248");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA108] DSA-108-1 wmtv");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-108-1 wmtv");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'wmtv', release: '2.2', reference: '0.6.5-2potato2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package wmtv is vulnerable in Debian 2.2.\nUpgrade to wmtv_0.6.5-2potato2\n');
}
if (w) { security_hole(port: 0, data: desc); }
