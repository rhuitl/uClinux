# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200608-06.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(22148);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200608-06");
 script_cve_id("CVE-2006-2659");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200608-06
(Courier MTA: Denial of Service vulnerability)


    Courier MTA has fixed a security issue relating to usernames containing
    the "=" character, causing high CPU utilization.
  
Impact

    An attacker could exploit this vulnerability by sending a specially
    crafted email to a mail gateway running a vulnerable version of Courier
    MTA.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2659


Solution: 
    All Courier MTA users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-mta/courier-0.53.2"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200608-06] Courier MTA: Denial of Service vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Courier MTA: Denial of Service vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "mail-mta/courier", unaffected: make_list("ge 0.53.2"), vulnerable: make_list("lt 0.53.2")
)) { security_warning(0); exit(0); }
