# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-37.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16428);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200501-37");
 script_cve_id("CVE-2005-0005");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200501-37
(GraphicsMagick: PSD decoding heap overflow)


    Andrei Nigmatulin discovered that handling a Photoshop Document
    (PSD) file with more than 24 layers in ImageMagick could trigger a heap
    overflow (GLSA 200501-26). GraphicsMagick is based on the same code and
    therefore suffers from the same flaw.
  
Impact

    An attacker could potentially design a malicious PSD image file to
    cause arbitrary code execution with the permissions of the user running
    GraphicsMagick.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0005
    http://www.gentoo.org/security/en/glsa/glsa-200501-26.xml


Solution: 
    All GraphicsMagick users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-gfx/graphicsmagick-1.1.5"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200501-37] GraphicsMagick: PSD decoding heap overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'GraphicsMagick: PSD decoding heap overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-gfx/graphicsmagick", unaffected: make_list("ge 1.1.5"), vulnerable: make_list("lt 1.1.5")
)) { security_warning(0); exit(0); }
