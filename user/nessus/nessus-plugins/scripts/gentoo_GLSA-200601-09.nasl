# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200601-09.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20419);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200601-09");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200601-09
(Wine: Windows Metafile SETABORTPROC vulnerability)


    H D Moore discovered that Wine implements the insecure-by-design
    SETABORTPROC GDI Escape function for Windows Metafile (WMF) files.
  
Impact

    An attacker could entice a user to open a specially crafted
    Windows Metafile (WMF) file from within a Wine executed Windows
    application, possibly resulting in the execution of arbitrary code with
    the rights of the user running Wine.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0106


Solution: 
    All Wine users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-emulation/wine-20050930"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200601-09] Wine: Windows Metafile SETABORTPROC vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Wine: Windows Metafile SETABORTPROC vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-emulation/wine", unaffected: make_list("ge 20050930"), vulnerable: make_list("lt 20050930")
)) { security_warning(0); exit(0); }
