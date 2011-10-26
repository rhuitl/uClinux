# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200505-07.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18233);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200505-07");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200505-07
(libTIFF: Buffer overflow)


    Tavis Ormandy of the Gentoo Linux Security Audit Team discovered a
    stack based buffer overflow in the libTIFF library when reading a TIFF
    image with a malformed BitsPerSample tag.
  
Impact

    Successful exploitation would require the victim to open a
    specially crafted TIFF image, resulting in the execution of arbitrary
    code.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://bugzilla.remotesensing.org/show_bug.cgi?id=843


Solution: 
    All libTIFF users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/tiff-3.7.2"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200505-07] libTIFF: Buffer overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'libTIFF: Buffer overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-libs/tiff", unaffected: make_list("ge 3.7.2"), vulnerable: make_list("lt 3.7.2")
)) { security_warning(0); exit(0); }
