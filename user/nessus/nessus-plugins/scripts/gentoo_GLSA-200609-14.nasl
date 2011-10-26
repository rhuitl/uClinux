# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200609-14.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(22458);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200609-14");
 script_cve_id("CVE-2006-3743", "CVE-2006-3744", "CVE-2006-4144");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200609-14
(ImageMagick: Multiple Vulnerabilities)


    Tavis Ormandy of the Google Security Team discovered a stack and heap
    buffer overflow in the GIMP XCF Image decoder and multiple heap and
    integer overflows in the SUN bitmap decoder. Damian Put discovered a
    heap overflow in the SGI image decoder.
  
Impact

    An attacker may be able to create a specially crafted image that, when
    processed with ImageMagick, executes arbitrary code with the privileges
    of the executing user.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3743
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3744
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4144


Solution: 
    All ImageMagick users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-gfx/imagemagick-6.2.9.5"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200609-14] ImageMagick: Multiple Vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ImageMagick: Multiple Vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-gfx/imagemagick", unaffected: make_list("ge 6.2.9.5"), vulnerable: make_list("lt 6.2.9.5")
)) { security_warning(0); exit(0); }
