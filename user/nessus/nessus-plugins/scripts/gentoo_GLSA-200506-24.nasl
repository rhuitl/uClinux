# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200506-24.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18590);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200506-24");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200506-24
(Heimdal: Buffer overflow vulnerabilities)


    It has been reported that the "getterminaltype" function of
    Heimdal\'s telnetd server is vulnerable to buffer overflows.
  
Impact

    An attacker could exploit this vulnerability to execute arbitrary
    code with the permission of the telnetd server program.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2040
    http://www.pdc.kth.se/heimdal/advisory/2005-06-20/


Solution: 
    All users should upgrade to the latest available version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-crypt/heimdal-0.6.5"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200506-24] Heimdal: Buffer overflow vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Heimdal: Buffer overflow vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-crypt/heimdal", unaffected: make_list("ge 0.6.5"), vulnerable: make_list("lt 0.6.5")
)) { security_hole(0); exit(0); }
