# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200602-09.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20935);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200602-09");
 script_cve_id("CVE-2006-0460");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200602-09
(BomberClone: Remote execution of arbitrary code)


    Stefan Cornelius of the Gentoo Security team discovered multiple
    missing buffer checks in BomberClone\'s code.
  
Impact

    By sending overly long error messages to the game via network, a
    remote attacker may exploit buffer overflows to execute arbitrary code
    with the rights of the user running BomberClone.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0460


Solution: 
    All BomberClone users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=games-action/bomberclone-0.11.6.2-r1"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200602-09] BomberClone: Remote execution of arbitrary code");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'BomberClone: Remote execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "games-action/bomberclone", unaffected: make_list("ge 0.11.6.2-r1"), vulnerable: make_list("lt 0.11.6.2-r1")
)) { security_hole(0); exit(0); }
