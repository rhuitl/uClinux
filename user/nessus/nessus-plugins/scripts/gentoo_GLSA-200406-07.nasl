# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200406-07.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14518);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200406-07");
 script_cve_id("CVE-2004-0413");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200406-07
(Subversion: Remote heap overflow)


    The svn protocol parser trusts the indicated length of a URI string sent by
    a client. This allows a client to specify a very long string, thereby
    causing svnserve to allocate enough memory to hold that string. This may
    cause a Denial of Service. Alternately, given a string that causes an
    integer overflow in the variable holding the string length, the server
    might allocate less memory than required, allowing a heap overflow. This
    heap overflow may then be exploitable, allowing remote code execution. The
    attacker does not need read or write access to the Subversion repository
    being served, since even un-authenticated users can send svn protocol
    requests.
  
Impact

    Ranges from remote Denial of Service to potential arbitrary code execution
    with privileges of the svnserve process.
  
Workaround

    Servers without svnserve running are not vulnerable. Disable svnserve and
    use DAV for access instead.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0413


Solution: 
    All users should upgrade to the latest version of Subversion.
    # emerge sync
    # emerge -pv ">=dev-util/subversion-1.0.4-r1"
    # emerge ">=dev-util/subversion-1.0.4-r1"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200406-07] Subversion: Remote heap overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Subversion: Remote heap overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-util/subversion", unaffected: make_list("ge 1.0.4-r1"), vulnerable: make_list("le 1.0.4")
)) { security_hole(0); exit(0); }
