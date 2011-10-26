# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200503-21.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(17353);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200503-21");
 script_cve_id("CVE-2005-0706");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200503-21
(Grip: CDDB response overflow)


    Joseph VanAndel has discovered a buffer overflow in Grip when
    processing large CDDB results.
  
Impact

    A malicious CDDB server could cause Grip to crash by returning
    more then 16 matches, potentially allowing the execution of arbitrary
    code with the privileges of the user running the application.
  
Workaround

    Disable automatic CDDB queries, but we highly encourage users to
    upgrade to 3.3.0.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0706
    http://sourceforge.net/tracker/?group_id=3714&atid=103714&func=detail&aid=834724


Solution: 
    All Grip users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-sound/grip-3.3.0"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200503-21] Grip: CDDB response overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Grip: CDDB response overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-sound/grip", unaffected: make_list("ge 3.3.0"), vulnerable: make_list("lt 3.3.0")
)) { security_warning(0); exit(0); }
