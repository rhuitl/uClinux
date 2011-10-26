# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200405-13.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14499);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200405-13");
 script_cve_id("CVE-2004-0398");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200405-13
(neon heap-based buffer overflow)


    Stefan Esser discovered a vulnerability in the code of the neon library :
    if a malicious date string is passed to the ne_rfc1036_parse() function, it
    can trigger a string overflow into static heap variables.
  
Impact

    Depending on the application linked against libneon and when connected to a
    malicious WebDAV server, this vulnerability could allow execution of
    arbitrary code with the rights of the user running that application.
  
Workaround

    There is no known workaround at this time. All users are advised to upgrade
    to the latest available version of neon.
  
References:
    http://security.e-matters.de/advisories/062004.html
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0398


Solution: 
    All users of neon should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=net-misc/neon-0.24.6"
    # emerge ">=net-misc/neon-0.24.6"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200405-13] neon heap-based buffer overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'neon heap-based buffer overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-misc/neon", unaffected: make_list("ge 0.24.6"), vulnerable: make_list("le 0.24.5")
)) { security_warning(0); exit(0); }
