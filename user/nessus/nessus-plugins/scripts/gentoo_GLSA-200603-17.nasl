# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200603-17.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21124);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200603-17");
 script_cve_id("CAN-2006-1148");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200603-17
(PeerCast: Buffer overflow)


    INFIGO discovered a problem in the URL handling code. Buffers that
    are allocated on the stack can be overflowed inside of nextCGIarg()
    function.
  
Impact

    By sending a specially crafted request to the HTTP server, a
    remote attacker can cause a stack overflow, resulting in the execution
    of arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2006-1148


Solution: 
    All PeerCast users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-sound/peercast-0.1217"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200603-17] PeerCast: Buffer overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PeerCast: Buffer overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-sound/peercast", unaffected: make_list("ge 0.1217"), vulnerable: make_list("lt 0.1217")
)) { security_hole(0); exit(0); }
