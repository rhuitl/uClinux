# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-30.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14798);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200409-30");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200409-30
(xine-lib: Multiple vulnerabilities)


    xine-lib contains two stack-based overflows and one heap-based overflow. In
    the code reading VCD disc labels, the ISO disc label is copied into an
    unprotected stack buffer of fixed size. Also, there is a buffer overflow in
    the code that parses subtitles and prepares them for display (XSA-2004-4).
    Finally, xine-lib contains a heap-based overflow in the DVD sub-picture
    decoder (XSA-2004-5).
     (Please note that the VCD MRL issue mentioned in XSA-2004-4 was fixed
    with GLSA 200408-18.)
  
Impact

    With carefully-crafted VCDs, DVDs, MPEGs or subtitles, an attacker may
    cause xine-lib to execute arbitrary code with the permissions of the user.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.securityfocus.com/archive/1/375485/2004-09-02/2004-09-08/0
    http://www.securityfocus.com/archive/1/375482/2004-09-02/2004-09-08/0


Solution: 
    All xine-lib users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=media-libs/xine-lib-1_rc6"
    # emerge ">=media-libs/xine-lib-1_rc6"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200409-30] xine-lib: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'xine-lib: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-libs/xine-lib", unaffected: make_list("ge 1_rc6"), vulnerable: make_list("le 1_rc5-r3")
)) { security_warning(0); exit(0); }
