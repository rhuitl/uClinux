# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200411-14.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15648);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200411-14");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200411-14
(Kaffeine, gxine: Remotely exploitable buffer overflow)


    KF of Secure Network Operations has discovered an overflow that occurs during the Content-Type header processing of Kaffeine. The vulnerable code in Kaffeine is reused from gxine, making gxine vulnerable as well.
  
Impact

    An attacker could create a specially-crafted Content-type header from a malicious HTTP server, and crash a user\'s instance of Kaffeine or gxine, potentially allowing the execution of arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://securitytracker.com/alerts/2004/Oct/1011936.html
    http://sourceforge.net/tracker/index.php?func=detail&aid=1060299&group_id=9655&atid=109655


Solution: 
    All Kaffeine users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-video/kaffeine-0.4.3b-r1"
    All gxine users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-video/gxine-0.3.3-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200411-14] Kaffeine, gxine: Remotely exploitable buffer overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Kaffeine, gxine: Remotely exploitable buffer overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-video/kaffeine", unaffected: make_list("ge 0.5_rc1-r1", "rge 0.4.3b-r1"), vulnerable: make_list("lt 0.5_rc1-r1")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "media-video/gxine", unaffected: make_list("ge 0.3.3-r1"), vulnerable: make_list("lt 0.3.3-r1")
)) { security_warning(0); exit(0); }
