# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200603-21.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21128);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200603-21");
 script_cve_id("CVE-2006-0058");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200603-21
(Sendmail: Race condition in the handling of asynchronous signals)


    ISS discovered that Sendmail is vulnerable to a race condition in
    the handling of asynchronous signals.
  
Impact

    An attacker could exploit this via certain crafted timing
    conditions.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0058
    http://www.sendmail.com/company/advisory/index.shtml


Solution: 
    All Sendmail users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-mta/sendmail-8.13.6"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200603-21] Sendmail: Race condition in the handling of asynchronous signals");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Sendmail: Race condition in the handling of asynchronous signals');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "mail-mta/sendmail", unaffected: make_list("ge 8.13.6"), vulnerable: make_list("lt 8.13.6")
)) { security_hole(0); exit(0); }
