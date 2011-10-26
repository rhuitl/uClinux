# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200605-04.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21319);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200605-04");
 script_cve_id("CVE-2006-1819");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200605-04
(phpWebSite: Local file inclusion)


    rgod has reported that the "hub_dir" parameter in "index.php"
    isn\'t properly verified. When "magic_quotes_gpc" is disabled, this can
    be exploited to include arbitrary files from local ressources.
  
Impact

    If "magic_quotes_gpc" is disabled, which is not the default on
    Gentoo Linux, a remote attacker could exploit this issue to include and
    execute PHP scripts from local ressources with the rights of the user
    running the web server, or to disclose sensitive information and
    potentially compromise a vulnerable system.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1819


Solution: 
    All phpWebSite users should upgrade to the latest available
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/phpwebsite-0.10.2"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200605-04] phpWebSite: Local file inclusion");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'phpWebSite: Local file inclusion');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-apps/phpwebsite", unaffected: make_list("ge 0.10.2"), vulnerable: make_list("lt 0.10.2")
)) { security_warning(0); exit(0); }
