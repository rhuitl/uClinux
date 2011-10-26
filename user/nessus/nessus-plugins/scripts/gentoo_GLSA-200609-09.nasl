# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200609-09.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(22354);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200609-09");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200609-09
(FFmpeg: Buffer overflows)


    FFmpeg contains buffer overflows in the AVI processing code.
  
Impact

    An attacker could trigger the buffer overflows by enticing a user to
    load a specially crafted AVI file in an application using the FFmpeg
    library. This might result in the execution of arbitrary code in the
    context of the running application.
  
Workaround

    There is no known workaround at this time.
  

Solution: 
    All FFmpeg users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-video/ffmpeg-0.4.9_p20060530"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200609-09] FFmpeg: Buffer overflows");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'FFmpeg: Buffer overflows');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-video/ffmpeg", unaffected: make_list("ge 0.4.9_p20060530"), vulnerable: make_list("lt 0.4.9_p20060530")
)) { security_warning(0); exit(0); }
