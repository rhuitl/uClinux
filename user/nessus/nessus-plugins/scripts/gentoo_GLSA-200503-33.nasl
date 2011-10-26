# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200503-33.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(17642);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200503-33");
 script_cve_id("CVE-2005-0398");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200503-33
(IPsec-Tools: racoon Denial of Service)


    Sebastian Krahmer has reported a potential remote Denial of
    Service vulnerability in the ISAKMP header parsing code of racoon.
  
Impact

    An attacker could possibly cause a Denial of Service of racoon
    using a specially crafted ISAKMP packet.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0398
    http://sourceforge.net/mailarchive/forum.php?thread_id=6787713&forum_id=32000


Solution: 
    All IPsec-Tools users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-firewall/ipsec-tools-0.4-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200503-33] IPsec-Tools: racoon Denial of Service");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'IPsec-Tools: racoon Denial of Service');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-firewall/ipsec-tools", unaffected: make_list("rge 0.4-r1", "ge 0.5-r1"), vulnerable: make_list("lt 0.5-r1")
)) { security_warning(0); exit(0); }
