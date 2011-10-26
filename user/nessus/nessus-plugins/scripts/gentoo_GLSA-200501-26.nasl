# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-26.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16417);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200501-26");
 script_cve_id("CVE-2005-0005");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200501-26
(ImageMagick: PSD decoding heap overflow)


    Andrei Nigmatulin discovered that a Photoshop Document (PSD) file
    with more than 24 layers could trigger a heap overflow.
  
Impact

    An attacker could potentially design a mailicous PSD image file to
    cause arbitrary code execution with the permissions of the user running
    ImageMagick.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0005
    http://www.idefense.com/application/poi/display?id=184&type=vulnerabilities


Solution: 
    All ImageMagick users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-gfx/imagemagick-6.1.8.8"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200501-26] ImageMagick: PSD decoding heap overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ImageMagick: PSD decoding heap overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-gfx/imagemagick", unaffected: make_list("ge 6.1.8.8"), vulnerable: make_list("lt 6.1.8.8")
)) { security_warning(0); exit(0); }
