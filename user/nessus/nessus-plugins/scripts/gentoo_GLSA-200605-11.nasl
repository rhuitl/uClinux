# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200605-11.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21353);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200605-11");
 script_cve_id("CVE-2006-1931");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200605-11
(Ruby: Denial of Service)


    Ruby uses blocking sockets for WEBrick and XMLRPC servers.
  
Impact

    An attacker could send large amounts of data to an affected server
    to block the socket and thus deny other connections to the server.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1931
    http://www.ruby-lang.org/en/20051224.html


Solution: 
    All Ruby users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-lang/ruby-1.8.4-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200605-11] Ruby: Denial of Service");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Ruby: Denial of Service');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-lang/ruby", unaffected: make_list("ge 1.8.4-r1"), vulnerable: make_list("lt 1.8.4-r1")
)) { security_warning(0); exit(0); }
