# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200605-12.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21354);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200605-12");
 script_cve_id("CVE-2006-2236");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200605-12
(Quake 3 engine based games: Buffer Overflow)


    landser discovered a vulnerability within the "remapShader"
    command. Due to a boundary handling error in "remapShader", there is a
    possibility of a buffer overflow.
  
Impact

    An attacker could set up a malicious game server and entice users
    to connect to it, potentially resulting in the execution of arbitrary
    code with the rights of the game user.
  
Workaround

    Do not connect to untrusted game servers.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2236


Solution: 
    All Quake 3 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=games-fps/quake3-bin-1.32c"
    All RTCW users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=games-fps/rtcw-1.41b"
    All Enemy Territory users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=games-fps/enemy-territory-2.60b"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200605-12] Quake 3 engine based games: Buffer Overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Quake 3 engine based games: Buffer Overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "games-fps/rtcw", unaffected: make_list("ge 1.41b"), vulnerable: make_list("lt 1.41b")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "games-fps/enemy-territory", unaffected: make_list("ge 2.60b"), vulnerable: make_list("lt 2.60b")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "games-fps/quake3-bin", unaffected: make_list("ge 1.32c"), vulnerable: make_list("lt 1.32c")
)) { security_warning(0); exit(0); }
