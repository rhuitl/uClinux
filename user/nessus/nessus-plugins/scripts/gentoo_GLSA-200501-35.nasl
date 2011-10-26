# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-35.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16426);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200501-35");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200501-35
(Evolution: Integer overflow in camel-lock-helper)


    Max Vozeler discovered an integer overflow in the
    camel-lock-helper application, which is installed as setgid mail by
    default.
  
Impact

    A local attacker could exploit this vulnerability to execute
    malicious code with the privileges of the \'mail\' group. A remote
    attacker could also setup a malicious POP server to execute arbitrary
    code when an Evolution user connects to it.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0102


Solution: 
    All Evolution users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-client/evolution-2.0.2-r1"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200501-35] Evolution: Integer overflow in camel-lock-helper");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Evolution: Integer overflow in camel-lock-helper');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "mail-client/evolution", unaffected: make_list("ge 2.0.2-r1"), vulnerable: make_list("le 2.0.2")
)) { security_hole(0); exit(0); }
