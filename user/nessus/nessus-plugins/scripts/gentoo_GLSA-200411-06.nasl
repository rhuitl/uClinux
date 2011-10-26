# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200411-06.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15608);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200411-06");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200411-06
(MIME-tools: Virus detection evasion)


    MIME-tools doesn\'t correctly parse attachment boundaries with an empty name
    (boundary="").
  
Impact

    An attacker could send a carefully crafted email and evade detection on
    some email virus-scanning programs using MIME-tools for attachment
    decoding.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://lists.roaringpenguin.com/pipermail/mimedefang/2004-October/024959.html


Solution: 
    All MIME-tools users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-perl/MIME-tools-5.415"
  

Risk factor : Low
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200411-06] MIME-tools: Virus detection evasion");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'MIME-tools: Virus detection evasion');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-perl/MIME-tools", unaffected: make_list("ge 5.415"), vulnerable: make_list("lt 5.415")
)) { security_warning(0); exit(0); }
