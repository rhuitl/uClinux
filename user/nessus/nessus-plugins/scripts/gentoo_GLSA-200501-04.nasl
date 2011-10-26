# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-04.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16395);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200501-04");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200501-04
(Shoutcast Server: Remote code execution)


    Part of the Shoutcast Server Linux binary has been found to
    improperly handle sprintf() parsing.
  
Impact

    A malicious attacker could send a formatted URL request to the
    Shoutcast Server. This formatted URL would cause either the server
    process to crash, or the execution of arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.securityfocus.com/archive/1/385350


Solution: 
    All Shoutcast Server users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-sound/shoutcast-server-bin-1.9.5"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200501-04] Shoutcast Server: Remote code execution");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Shoutcast Server: Remote code execution');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-sound/shoutcast-server-bin", unaffected: make_list("ge 1.9.5"), vulnerable: make_list("le 1.9.4-r1")
)) { security_warning(0); exit(0); }
