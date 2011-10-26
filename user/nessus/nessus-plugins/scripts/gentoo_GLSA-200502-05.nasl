# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200502-05.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16442);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200502-05");
 script_cve_id("CVE-2005-0101");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200502-05
(Newspost: Buffer overflow vulnerability)


    Niels Heinen has discovered a buffer overflow in the socket_getline()
    function of Newspost, which can be triggered by providing long strings
    that do not end with a newline character.
  
Impact

    A remote attacker could setup a malicious NNTP server and entice a
    Newspost user to post to it, leading to the crash of the Newspost
    process and potentially the execution of arbitrary code with the rights
    of the Newspost user.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0101


Solution: 
    All Newspost users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-nntp/newspost-2.0-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200502-05] Newspost: Buffer overflow vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Newspost: Buffer overflow vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-nntp/newspost", unaffected: make_list("rge 2.0-r1", "ge 2.1.1-r1"), vulnerable: make_list("lt 2.1.1-r1")
)) { security_warning(0); exit(0); }
