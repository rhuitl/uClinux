# This script was automatically generated from the dsa-915
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
An integer overflow has been discovered in helix-player, the helix
audio and video player.  This flaw could allow a remote attacker to
run arbitrary code on a victims computer by supplying a specially
crafted network resource.
The old stable distribution (woody) does not contain a helix-player
package.
For the stable distribution (sarge) these problems have been fixed in
version 1.0.4-1sarge2.
For the unstable distribution (sid) these problems have been fixed in
version 1.0.6-1.
We recommend that you upgrade your helix-player package.


Solution : http://www.debian.org/security/2005/dsa-915
Risk factor : High';

if (description) {
 script_id(22781);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "915");
 script_cve_id("CVE-2005-2629");
 script_bugtraq_id(15381);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA915] DSA-915-1 helix-player");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-915-1 helix-player");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'helix-player', release: '', reference: '1.0.6-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package helix-player is vulnerable in Debian .\nUpgrade to helix-player_1.0.6-1\n');
}
if (deb_check(prefix: 'helix-player', release: '3.1', reference: '1.0.4-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package helix-player is vulnerable in Debian 3.1.\nUpgrade to helix-player_1.0.4-1sarge2\n');
}
if (deb_check(prefix: 'helix-player', release: '3.1', reference: '1.0.4-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package helix-player is vulnerable in Debian sarge.\nUpgrade to helix-player_1.0.4-1sarge2\n');
}
if (w) { security_hole(port: 0, data: desc); }
