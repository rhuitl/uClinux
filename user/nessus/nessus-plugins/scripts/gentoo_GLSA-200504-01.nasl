# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200504-01.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(17675);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200504-01");
 script_cve_id("CVE-2005-0468", "CVE-2005-0469");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200504-01
(telnet-bsd: Multiple buffer overflows)


    A buffer overflow has been identified in the env_opt_add()
    function of telnet-bsd, where a response requiring excessive escaping
    can cause a heap-based buffer overflow. Another issue has been
    identified in the slc_add_reply() function, where a large number of SLC
    commands can overflow a fixed size buffer.
  
Impact

    Successful exploitation would require a vulnerable user to connect
    to an attacker-controlled host using telnet, potentially executing
    arbitrary code with the permissions of the telnet user.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0468
    http://www.idefense.com/application/poi/display?id=221&type=vulnerabilities
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0469
    http://www.idefense.com/application/poi/display?id=220&type=vulnerabilities


Solution: 
    All telnet-bsd users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/telnet-bsd-1.0-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200504-01] telnet-bsd: Multiple buffer overflows");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'telnet-bsd: Multiple buffer overflows');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-misc/telnet-bsd", unaffected: make_list("ge 1.0-r1"), vulnerable: make_list("lt 1.0-r1")
)) { security_warning(0); exit(0); }
