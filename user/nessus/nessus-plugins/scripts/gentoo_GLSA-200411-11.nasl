# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200411-11.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15645);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200411-11");
 script_cve_id("CVE-2004-0981");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200411-11
(ImageMagick: EXIF buffer overflow)


    ImageMagick fails to do proper bounds checking when handling image files
    with EXIF information.
  
Impact

    An attacker could use an image file with specially-crafted EXIF information
    to cause arbitrary code execution with the permissions of the user running
    ImageMagick.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0981
    http://www.imagemagick.org/www/Changelog.html
    http://secunia.com/advisories/12995/


Solution: 
    All ImageMagick users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-gfx/imagemagick-6.1.3.2"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200411-11] ImageMagick: EXIF buffer overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ImageMagick: EXIF buffer overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-gfx/imagemagick", unaffected: make_list("ge 6.1.3.2"), vulnerable: make_list("lt 6.1.3.2")
)) { security_warning(0); exit(0); }
