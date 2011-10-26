# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200608-09.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(22167);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200608-09");
 script_cve_id("CVE-2006-3469");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200608-09
(MySQL: Denial of Service)


    Jean-David Maillefer discovered a format string vulnerability in
    time.cc where MySQL fails to properly handle specially formatted user
    input to the date_format function.
  
Impact

    By specifying a format string as the first parameter to the date_format
    function, an authenticated attacker could cause MySQL to crash,
    resulting in a Denial of Service.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3469


Solution: 
    All MySQL users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --verbose --oneshot ">=dev-db/mysql-4.1.21"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200608-09] MySQL: Denial of Service");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'MySQL: Denial of Service');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-db/mysql", unaffected: make_list("ge 4.1.21"), vulnerable: make_list("lt 4.1.21")
)) { security_warning(0); exit(0); }
