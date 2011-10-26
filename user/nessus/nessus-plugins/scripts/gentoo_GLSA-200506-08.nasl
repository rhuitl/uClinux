# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200506-08.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18465);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200506-08");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200506-08
(GNU shtool, ocaml-mysql: Insecure temporary file creation)


    Eric Romang has discovered that GNU shtool insecurely creates
    temporary files with predictable filenames (CVE-2005-1751). On closer
    inspection, Gentoo Security discovered that the shtool temporary file,
    once created, was being reused insecurely (CVE-2005-1759).
  
Impact

    A local attacker could create symbolic links in the temporary
    files directory, pointing to a valid file somewhere on the filesystem.
    When a GNU shtool script is executed, this would result in the file
    being overwritten with the rights of the user running the script, which
    could be the root user.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1751
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1759


Solution: 
    All GNU shtool users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-util/shtool-2.0.1-r2"
    All ocaml-mysql users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-ml/ocaml-mysql-1.0.3-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200506-08] GNU shtool, ocaml-mysql: Insecure temporary file creation");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'GNU shtool, ocaml-mysql: Insecure temporary file creation');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-ml/ocaml-mysql", unaffected: make_list("ge 1.0.3-r1"), vulnerable: make_list("lt 1.0.3-r1")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "dev-util/shtool", unaffected: make_list("ge 2.0.1-r2"), vulnerable: make_list("lt 2.0.1-r2")
)) { security_warning(0); exit(0); }
