# This script was automatically generated from the dsa-189
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
iDEFENSE reported about a vulnerability in LuxMan, a maze game for
GNU/Linux, similar to the PacMan arcade game.  When successfully
exploited a local attacker gains read-write access to the memory,
leading to a local root compromise in many ways, examples of which
include scanning the file for fragments of the master password file
and modifying kernel memory to re-map system calls.
This problem has been fixed in version 0.41-17.1 for the current stable
distribution (woody) and in version 0.41-19 for the unstable
distribution (sid).  The old stable distribution (potato) is not
affected since it doesn\'t contain a luxman package.
We recommend that you upgrade your luxman package immediately.


Solution : http://www.debian.org/security/2002/dsa-189
Risk factor : High';

if (description) {
 script_id(15026);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "189");
 script_cve_id("CVE-2002-1245");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA189] DSA-189-1 luxman");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-189-1 luxman");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'luxman', release: '3.0', reference: '0.41-17.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package luxman is vulnerable in Debian 3.0.\nUpgrade to luxman_0.41-17.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
