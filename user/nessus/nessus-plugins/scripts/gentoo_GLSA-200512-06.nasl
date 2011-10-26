# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200512-06.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20315);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200512-06");
 script_cve_id("CVE-2005-3651");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200512-06
(Ethereal: Buffer overflow in OSPF protocol dissector)


    iDEFENSE reported a possible overflow due to the lack of bounds
    checking in the dissect_ospf_v3_address_prefix() function, part of the
    OSPF protocol dissector.
  
Impact

    An attacker might be able to craft a malicious network flow that
    would crash Ethereal. It may be possible, though unlikely, to exploit
    this flaw to execute arbitrary code with the permissions of the user
    running Ethereal, which could be the root user.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3651
    http://www.idefense.com/application/poi/display?id=349&type=vulnerabilities


Solution: 
    All Ethereal users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-analyzer/ethereal-0.10.13-r2"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200512-06] Ethereal: Buffer overflow in OSPF protocol dissector");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Ethereal: Buffer overflow in OSPF protocol dissector');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-analyzer/ethereal", unaffected: make_list("ge 0.10.13-r2"), vulnerable: make_list("lt 0.10.13-r2")
)) { security_hole(0); exit(0); }
