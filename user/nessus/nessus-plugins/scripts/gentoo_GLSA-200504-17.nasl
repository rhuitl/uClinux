# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200504-17.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18089);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200504-17");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200504-17
(XV: Multiple vulnerabilities)


    Greg Roelofs has reported multiple input validation errors in XV
    image decoders. Tavis Ormandy of the Gentoo Linux Security Audit Team
    has reported insufficient validation in the PDS (Planetary Data System)
    image decoder, format string vulnerabilities in the TIFF and PDS
    decoders, and insufficient protection from shell meta-characters in
    malformed filenames.
  
Impact

    Successful exploitation would require a victim to view a specially
    created image file using XV, potentially resulting in the execution of
    arbitrary code.
  
Workaround

    There is no known workaround at this time.
  

Solution: 
    All XV users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-gfx/xv-3.10a-r11"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200504-17] XV: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'XV: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-gfx/xv", unaffected: make_list("ge 3.10a-r11"), vulnerable: make_list("lt 3.10a-r11")
)) { security_warning(0); exit(0); }
