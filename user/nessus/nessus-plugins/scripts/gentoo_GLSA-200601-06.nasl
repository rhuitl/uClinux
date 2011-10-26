# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200601-06.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20416);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200601-06");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200601-06
(xine-lib, FFmpeg: Heap-based buffer overflow)


    Simon Kilvington has reported a vulnerability in FFmpeg
    libavcodec. The flaw is due to a buffer overflow error in the
    "avcodec_default_get_buffer()" function. This function doesn\'t properly
    handle specially crafted PNG files as a result of a heap overflow.
  
Impact

    A remote attacker could entice a user to run an FFmpeg based
    application on a maliciously crafted PNG file, resulting in the
    execution of arbitrary code with the permissions of the user running
    the application.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-4048
    http://article.gmane.org/gmane.comp.video.ffmpeg.devel/26558


Solution: 
    All xine-lib users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/xine-lib-1.1.1-r3"
    All FFmpeg users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-video/ffmpeg-0.4.9_p20051216"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200601-06] xine-lib, FFmpeg: Heap-based buffer overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'xine-lib, FFmpeg: Heap-based buffer overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-libs/xine-lib", unaffected: make_list("ge 1.1.1-r3"), vulnerable: make_list("lt 1.1.1-r3")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "media-video/ffmpeg", unaffected: make_list("ge 0.4.9_p20051216"), vulnerable: make_list("lt 0.4.9_p20051216")
)) { security_warning(0); exit(0); }
