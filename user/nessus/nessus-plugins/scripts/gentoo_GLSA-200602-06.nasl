# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200602-06.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20896);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200602-06");
 script_cve_id("CVE-2006-0082");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200602-06
(ImageMagick: Format string vulnerability)


    The SetImageInfo function was found vulnerable to a format string
    mishandling. Daniel Kobras discovered that the handling of "%"-escaped
    sequences in filenames passed to the function is inadequate. This is a
    new vulnerability that is not addressed by GLSA 200503-11.
  
Impact

    By feeding specially crafted file names to ImageMagick, an
    attacker can crash the program and possibly execute arbitrary code with
    the privileges of the user running ImageMagick.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0082
    http://www.gentoo.org/security/en/glsa/glsa-200503-11.xml


Solution: 
    All ImageMagick users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-gfx/imagemagick-6.2.5.5"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200602-06] ImageMagick: Format string vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ImageMagick: Format string vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-gfx/imagemagick", unaffected: make_list("ge 6.2.5.5"), vulnerable: make_list("lt 6.2.5.5")
)) { security_warning(0); exit(0); }
