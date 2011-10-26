# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200603-16.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21097);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200603-16");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200603-16
(Metamail: Buffer overflow)


    Ulf Harnhammar discovered a buffer overflow in Metamail when
    processing mime boundraries.
  
Impact

    By sending a specially crafted email, attackers could potentially
    exploit this vulnerability to crash Metamail or to execute arbitrary
    code.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0709


Solution: 
    All Metamail users should update to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-mail/metamail-2.7.45.3-r1"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200603-16] Metamail: Buffer overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Metamail: Buffer overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-mail/metamail", unaffected: make_list("ge 2.7.45.3-r1"), vulnerable: make_list("lt 2.7.45.3-r1")
)) { security_hole(0); exit(0); }
