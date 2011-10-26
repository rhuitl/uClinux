# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200602-01.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20864);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200602-01");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200602-01
(GStreamer FFmpeg plugin: Heap-based buffer overflow)


    The GStreamer FFmpeg plugin contains derived code from the FFmpeg
    library, which is vulnerable to a heap overflow in the
    "avcodec_default_get_buffer()" function discovered by Simon Kilvington
    (see GLSA 200601-06).
  
Impact

    A remote attacker could entice a user to run an application using
    the GStreamer FFmpeg plugin on a maliciously crafted PIX_FMT_PAL8
    format image file (like PNG images), possibly leading to the execution
    of arbitrary code with the permissions of the user running the
    application.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-4048
    http://www.gentoo.org/security/en/glsa/glsa-200601-06.xml


Solution: 
    All GStreamer FFmpeg plugin users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-plugins/gst-plugins-ffmpeg-0.8.7-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200602-01] GStreamer FFmpeg plugin: Heap-based buffer overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'GStreamer FFmpeg plugin: Heap-based buffer overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-plugins/gst-plugins-ffmpeg", unaffected: make_list("ge 0.8.7-r1"), vulnerable: make_list("lt 0.8.7-r1")
)) { security_warning(0); exit(0); }
