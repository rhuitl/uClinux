# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200412-11.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15989);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200412-11");
 script_cve_id("CVE-2004-0996");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200412-11
(Cscope: Insecure creation of temporary files)


    Cscope creates temporary files in world-writable directories with
    predictable names.
  
Impact

    A local attacker could create symbolic links in the temporary
    files directory, pointing to a valid file somewhere on the filesystem.
    When Cscope is executed, this would result in the file being
    overwritten with the rights of the user running the utility, which
    could be the root user.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0996
    http://www.securityfocus.com/archive/1/381443


Solution: 
    All Cscope users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-util/cscope-15.5-r2"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200412-11] Cscope: Insecure creation of temporary files");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Cscope: Insecure creation of temporary files');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-util/cscope", unaffected: make_list("ge 15.5-r2"), vulnerable: make_list("lt 15.5-r2")
)) { security_warning(0); exit(0); }
