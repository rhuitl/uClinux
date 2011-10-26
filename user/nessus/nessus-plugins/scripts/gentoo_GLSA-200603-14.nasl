# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200603-14.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21095);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200603-14");
 script_cve_id("CAN-2006-0582");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200603-14
(Heimdal: rshd privilege escalation)


    An unspecified privilege escalation vulnerability in the rshd
    server of Heimdal has been reported.
  
Impact

    Authenticated users could exploit the vulnerability to escalate
    privileges or to change the ownership and content of arbitrary files.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2006-0582
    http://www.pdc.kth.se/heimdal/advisory/2006-02-06/


Solution: 
    All Heimdal users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-crypt/heimdal-0.7.2"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200603-14] Heimdal: rshd privilege escalation");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Heimdal: rshd privilege escalation');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-crypt/heimdal", unaffected: make_list("ge 0.7.2"), vulnerable: make_list("lt 0.7.2")
)) { security_warning(0); exit(0); }
