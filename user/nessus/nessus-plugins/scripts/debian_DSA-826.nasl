# This script was automatically generated from the dsa-826
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Multiple security vulnerabilities have been identified in the
helix-player media player that could allow an attacker to execute code
on the victim\'s machine via specially crafted network resources.
        Buffer overflow in the RealText parser could allow remote code
        execution via a specially crafted RealMedia file with a long
        RealText string.
        Format string vulnerability in Real HelixPlayer and RealPlayer 10
        allows remote attackers to execute arbitrary code via the image
        handle attribute in a RealPix (.rp) or RealText (.rt) file.
For the stable distribution (sarge), these problems have been fixed in
version 1.0.4-1sarge1
For the unstable distribution (sid), these problems have been fixed in
version 1.0.6-1
We recommend that you upgrade your helix-player package.
helix-player was distributed only on the i386 and powerpc architectures


Solution : http://www.debian.org/security/2005/dsa-826
Risk factor : High';

if (description) {
 script_id(19795);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "826");
 script_cve_id("CVE-2005-1766", "CVE-2005-2710");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA826] DSA-826-1 helix-player");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-826-1 helix-player");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'helix-player', release: '', reference: '1.0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package helix-player is vulnerable in Debian .\nUpgrade to helix-player_1.0\n');
}
if (deb_check(prefix: 'helix-player', release: '3.1', reference: '1.0.4-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package helix-player is vulnerable in Debian 3.1.\nUpgrade to helix-player_1.0.4-1sarge1\n');
}
if (deb_check(prefix: 'helix-player', release: '3.1', reference: '1.0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package helix-player is vulnerable in Debian sarge.\nUpgrade to helix-player_1.0\n');
}
if (w) { security_hole(port: 0, data: desc); }
