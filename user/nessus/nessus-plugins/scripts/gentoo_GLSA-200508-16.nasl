# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200508-16.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19536);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200508-16");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200508-16
(Tor: Information disclosure)


    The Diffie-Hellman implementation of Tor fails to verify the
    cryptographic strength of keys which are used during handshakes.
  
Impact

    By setting up a malicious Tor server and enticing users to use
    this server as first hop, a remote attacker could read and modify all
    traffic of the user.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2643
    http://archives.seul.org/or/announce/Aug-2005/msg00002.html


Solution: 
    All Tor users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/tor-0.1.0.14"
  

Risk factor : Low
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200508-16] Tor: Information disclosure");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Tor: Information disclosure');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-misc/tor", unaffected: make_list("ge 0.1.0.14"), vulnerable: make_list("lt 0.1.0.14")
)) { security_warning(0); exit(0); }
