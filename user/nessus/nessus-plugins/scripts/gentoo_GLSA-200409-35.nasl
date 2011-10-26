# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-35.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15406);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200409-35");
 script_cve_id("CVE-2004-0749");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200409-35
(Subversion: Metadata information leak)


    There is a bug in mod_authz_svn that causes it to reveal logged metadata
    regarding commits to protected areas.
  
Impact

    Protected files themselves will not be revealed, but an attacker could use
    the metadata to reveal the existence of protected areas, such as paths,
    file versions, and the commit logs from those areas.
  
Workaround

    Rather than using mod_authz_svn, move protected areas into seperate
    repositories and use native Apache authentication to make these
    repositories unreadable.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0749
    http://subversion.tigris.org/security/CAN-2004-0749-advisory.txt


Solution: 
    All Subversion users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=dev-util/subversion-1.0.8"
    # emerge ">=dev-util/subversion-1.0.8"
  

Risk factor : Low
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200409-35] Subversion: Metadata information leak");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Subversion: Metadata information leak');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-util/subversion", unaffected: make_list("ge 1.0.8"), vulnerable: make_list("lt 1.0.8")
)) { security_warning(0); exit(0); }
