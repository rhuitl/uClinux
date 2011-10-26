# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200608-27.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(22289);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200608-27");
 script_cve_id("CVE-2005-3863");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200608-27
(Motor: Execution of arbitrary code)


    In November 2005, Zone-H Research reported a boundary error in the
    ktools library in the VGETSTRING() macro of kkstrtext.h, which may
    cause a buffer overflow via an overly long input string.
  
Impact

    A remote attacker could entice a user to use a malicious file or input,
    which could lead to the crash of Motor and possibly the execution of
    arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3863


Solution: 
    All Motor 3.3.x users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-util/motor-3.3.0-r1"
    All motor 3.4.x users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-util/motor-3.4.0-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200608-27] Motor: Execution of arbitrary code");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Motor: Execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-util/motor", unaffected: make_list("rge 3.3.0-r1", "ge 3.4.0-r1"), vulnerable: make_list("lt 3.4.0-r1")
)) { security_warning(0); exit(0); }
