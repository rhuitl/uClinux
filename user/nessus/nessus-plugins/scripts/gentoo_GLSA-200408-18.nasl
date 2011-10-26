# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200408-18.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14574);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200408-18");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200408-18
(xine-lib: VCD MRL buffer overflow)


    xine-lib contains a bug where it is possible to overflow the vcd:// input
    source identifier management buffer through carefully crafted playlists.
  
Impact

    An attacker may construct a carefully-crafted playlist file which will
    cause xine-lib to execute arbitrary code with the permissions of the user.
    In order to conform with the generic naming standards of most Unix-like
    systems, playlists can have extensions other than .asx (the standard xine
    playlist format), and made to look like another file (MP3, AVI, or MPEG for
    example). If an attacker crafts a playlist with a valid header, they can
    insert a VCD playlist line that can cause a buffer overflow and possible
    shellcode execution.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version of xine-lib.
  
References:
    http://www.open-security.org/advisories/6


Solution: 
    All xine-lib users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=media-libs/xine-lib-1_rc5-r3"
    # emerge ">=media-libs/xine-lib-1_rc5-r3"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200408-18] xine-lib: VCD MRL buffer overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'xine-lib: VCD MRL buffer overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-libs/xine-lib", unaffected: make_list("ge 1_rc5-r3"), vulnerable: make_list("le 1_rc5-r2")
)) { security_warning(0); exit(0); }
