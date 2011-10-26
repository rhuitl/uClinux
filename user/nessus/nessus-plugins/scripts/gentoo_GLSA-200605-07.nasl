# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200605-07.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21349);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200605-07");
 script_cve_id("CVE-2006-2162");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200605-07
(Nagios: Buffer overflow)


    Sebastian Krahmer of the SuSE security team discovered a buffer
    overflow vulnerability in the handling of a negative HTTP
    Content-Length header.
  
Impact

    A buffer overflow in Nagios CGI scripts under certain web servers
    allows remote attackers to execute arbitrary code via a negative
    content length HTTP header.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2162


Solution: 
    All Nagios users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-analyzer/nagios-core-1.4"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200605-07] Nagios: Buffer overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Nagios: Buffer overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-analyzer/nagios-core", unaffected: make_list("ge 1.4"), vulnerable: make_list("lt 1.4")
)) { security_hole(0); exit(0); }
