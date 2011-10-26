# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-03.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14650);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200409-03");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200409-03
(Python 2.2: Buffer overflow in getaddrinfo())


    If IPV6 is disabled in Python 2.2, getaddrinfo() is not able to handle IPV6
    DNS requests properly and a buffer overflow occurs.
  
Impact

    An attacker can execute arbitrary code as the user running python.
  
Workaround

    Users with IPV6 enabled are not affected by this vulnerability.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0150
    http://www.osvdb.org/4172


Solution: 
    All Python 2.2 users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=dev-lang/python-2.2.2"
    # emerge ">=dev-lang/python-2.2.2"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200409-03] Python 2.2: Buffer overflow in getaddrinfo()");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Python 2.2: Buffer overflow in getaddrinfo()');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-lang/python", unaffected: make_list("ge 2.2.2", "lt 2.2"), vulnerable: make_list("lt 2.2.2")
)) { security_hole(0); exit(0); }
