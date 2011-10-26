# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200610-05.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(22891);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200610-05");
 script_cve_id("CVE-2006-3126");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200610-05
(CAPI4Hylafax fax receiver: Execution of arbitrary code)


    Lionel Elie Mamane discovered an error in c2faxrecv, which doesn\'t
    properly sanitize TSI strings when handling incoming calls.
  
Impact

    A remote attacker can send null (\\0) and shell metacharacters in the
    TSI string from an anonymous fax number, leading to the execution of
    arbitrary code with the rights of the user running c2faxrecv.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3126


Solution: 
    All CAPI4Hylafax users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/capi4hylafax-01.03.00.99.300.3-r1"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200610-05] CAPI4Hylafax fax receiver: Execution of arbitrary code");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'CAPI4Hylafax fax receiver: Execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-misc/capi4hylafax", unaffected: make_list("ge 01.03.00.99.300.3-r1"), vulnerable: make_list("lt 01.03.00.99.300.3-r1")
)) { security_hole(0); exit(0); }
