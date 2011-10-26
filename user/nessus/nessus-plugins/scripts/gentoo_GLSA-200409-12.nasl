# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-12.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14677);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200409-12");
 script_cve_id("CVE-2004-0817", "CVE-2004-0802");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200409-12
(ImageMagick, imlib, imlib2: BMP decoding buffer overflows)


    Due to improper bounds checking, ImageMagick and imlib are vulnerable to a
    buffer overflow when decoding runlength-encoded bitmaps. This bug can be
    exploited using a specially-crafted BMP image and could potentially allow
    remote code execution when this image is decoded by the user.
  
Impact

    A specially-crafted runlength-encoded BMP could lead ImageMagick and imlib
    to crash or potentially execute arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0817
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0802
    http://studio.imagemagick.org/pipermail/magick-developers/2004-August/002011.html
    http://securitytracker.com/alerts/2004/Aug/1011104.html
    http://securitytracker.com/alerts/2004/Aug/1011105.html


Solution: 
    All ImageMagick users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=media-gfx/imagemagick-6.0.7.1"
    # emerge ">=media-gfx/imagemagick-6.0.7.1"
    All imlib users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=media-libs/imlib-1.9.14-r2"
    # emerge ">=media-libs/imlib-1.9.14-r2"
    All imlib2 users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=media-libs/imlib2-1.1.2"
    # emerge ">=media-libs/imlib2-1.1.2"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200409-12] ImageMagick, imlib, imlib2: BMP decoding buffer overflows");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ImageMagick, imlib, imlib2: BMP decoding buffer overflows');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-libs/imlib", unaffected: make_list("ge 1.9.14-r2"), vulnerable: make_list("lt 1.9.14-r2")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "media-gfx/imagemagick", unaffected: make_list("ge 6.0.7.1"), vulnerable: make_list("lt 6.0.7.1")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "media-libs/imlib2", unaffected: make_list("ge 1.1.2"), vulnerable: make_list("lt 1.1.2")
)) { security_warning(0); exit(0); }
