# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200607-02.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(22009);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200607-02");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200607-02
(FreeType: Multiple integer overflows)


    Multiple integer overflows exist in a variety of files (bdf/bdflib.c,
    sfnt/ttcmap.c, cff/cffgload.c, base/ftmac.c).
  
Impact

    A remote attacker could exploit these buffer overflows by enticing a
    user to load a specially crafted font, which could result in the
    execution of arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1861


Solution: 
    All FreeType users should upgrade to the latest stable version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/freetype-2.1.10-r2"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200607-02] FreeType: Multiple integer overflows");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'FreeType: Multiple integer overflows');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-libs/freetype", unaffected: make_list("ge 2.1.10-r2"), vulnerable: make_list("lt 2.1.10-r2")
)) { security_warning(0); exit(0); }
