# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200510-15.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20035);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200510-15");
 script_cve_id("CVE-2005-3120");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200510-15
(Lynx: Buffer overflow in NNTP processing)


    When accessing a NNTP URL, Lynx connects to a NNTP server and
    retrieves information about the available articles in the target
    newsgroup. Ulf Harnhammar discovered a buffer overflow in a function
    that handles the escaping of special characters.
  
Impact

    An attacker could setup a malicious NNTP server and entice a user
    to access it using Lynx (either by creating NNTP links on a web page or
    by forcing a redirect for Lynx users). The data returned by the NNTP
    server would trigger the buffer overflow and execute arbitrary code
    with the rights of the user running Lynx.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3120


Solution: 
    All Lynx users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/lynx-2.8.5-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200510-15] Lynx: Buffer overflow in NNTP processing");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Lynx: Buffer overflow in NNTP processing');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-client/lynx", unaffected: make_list("ge 2.8.5-r1"), vulnerable: make_list("lt 2.8.5-r1")
)) { security_warning(0); exit(0); }
