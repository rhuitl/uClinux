# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200505-16.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18380);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200505-16");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200505-16
(ImageMagick, GraphicsMagick: Denial of Service vulnerability)


    Tavis Ormandy of the Gentoo Linux Security Audit Team discovered a
    Denial of Service vulnerability in the XWD decoder of ImageMagick and
    GraphicsMagick when setting a color mask to zero.
  
Impact

    A remote attacker could submit a specially crafted image to a user
    or an automated system making use of an affected utility, resulting in
    a Denial of Service by consumption of CPU time.
  
Workaround

    There is no known workaround at this time.
  

Solution: 
    All ImageMagick users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-gfx/imagemagick-6.2.2.3"
    All GraphicsMagick users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-gfx/graphicsmagick-1.1.6-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200505-16] ImageMagick, GraphicsMagick: Denial of Service vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ImageMagick, GraphicsMagick: Denial of Service vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-gfx/graphicsmagick", unaffected: make_list("ge 1.1.6-r1"), vulnerable: make_list("lt 1.1.6-r1")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "media-gfx/imagemagick", unaffected: make_list("ge 6.2.2.3"), vulnerable: make_list("lt 6.2.2.3")
)) { security_warning(0); exit(0); }
