# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200503-04.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(17251);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200503-04");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200503-04
(phpWebSite: Arbitrary PHP execution and path disclosure)


    NST discovered that, when submitting an announcement, uploaded
    files aren\'t correctly checked for malicious code. They also found out
    that phpWebSite is vulnerable to a path disclosure.
  
Impact

    A remote attacker can exploit this issue to upload files to a
    directory within the web root. By calling the uploaded script the
    attacker could then execute arbitrary PHP code with the rights of the
    web server. By passing specially crafted requests to the search module,
    remote attackers can also find out the full path of PHP scripts.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://secunia.com/advisories/14399/
    http://phpwebsite.appstate.edu/index.php?module=announce&ANN_id=922&ANN_user_op=view


Solution: 
    All phpWebSite users should upgrade to the latest available
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/phpwebsite-0.10.0-r2"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200503-04] phpWebSite: Arbitrary PHP execution and path disclosure");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'phpWebSite: Arbitrary PHP execution and path disclosure');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-apps/phpwebsite", unaffected: make_list("ge 0.10.0-r2"), vulnerable: make_list("lt 0.10.0-r2")
)) { security_hole(0); exit(0); }
