# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200606-25.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21758);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200606-25");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200606-25
(Hashcash: Possible heap overflow)


    Andreas Seltenreich has reported a possible heap overflow in the
    array_push() function in hashcash.c, as a result of an incorrect amount
    of allocated memory for the "ARRAY" structure.
  
Impact

    By sending malicious entries to the Hashcash utility, an attacker may
    be able to cause an overflow, potentially resulting in the execution of
    arbitrary code with the privileges of the user running the application.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.hashcash.org/source/CHANGELOG


Solution: 
    All Hashcash users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/hashcash-1.21"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200606-25] Hashcash: Possible heap overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Hashcash: Possible heap overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-misc/hashcash", unaffected: make_list("ge 1.21"), vulnerable: make_list("lt 1.21")
)) { security_hole(0); exit(0); }
