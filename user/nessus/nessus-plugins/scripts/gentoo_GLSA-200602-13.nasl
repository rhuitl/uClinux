# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200602-13.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20979);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200602-13");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200602-13
(GraphicsMagick: Format string vulnerability)


    The SetImageInfo function was found vulnerable to a format string
    mishandling. Daniel Kobras discovered that the handling of "%"-escaped
    sequences in filenames passed to the function is inadequate in
    ImageMagick GLSA 200602-06 and the same vulnerability exists in
    GraphicsMagick.
  
Impact

    By feeding specially crafted file names to GraphicsMagick an
    attacker can crash the program and possibly execute arbitrary code with
    the privileges of the user running GraphicsMagick.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.gentoo.org/security/en/glsa/glsa-200602-06.xml


Solution: 
    All GraphicsMagick users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-gfx/graphicsmagick-1.1.7"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200602-13] GraphicsMagick: Format string vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'GraphicsMagick: Format string vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-gfx/graphicsmagick", unaffected: make_list("ge 1.1.7"), vulnerable: make_list("lt 1.1.7")
)) { security_warning(0); exit(0); }
