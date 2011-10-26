# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200507-09.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18668);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2005-t-0025");
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200507-09");
 script_cve_id("CVE-2005-1625");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200507-09
(Adobe Acrobat Reader: Buffer overflow vulnerability)


    A buffer overflow has been discovered in the
    UnixAppOpenFilePerform() function, which is called when Adobe Acrobat
    Reader tries to open a file with the "\\Filespec" tag.
  
Impact

    By enticing a user to open a specially crafted PDF document, a
    remote attacker could exploit this vulnerability to execute arbitrary
    code.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1625
    http://www.idefense.com/application/poi/display?id=279&type=vulnerabilities&flashstatus=true
    http://www.adobe.com/support/techdocs/329083.html


Solution: 
    Since Adobe will most likely not update the 5.0 series of Adobe
    Acrobat Reader for Linux, all users should upgrade to the latest
    available version of the 7.0 series:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/acroread-7.0"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200507-09] Adobe Acrobat Reader: Buffer overflow vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Adobe Acrobat Reader: Buffer overflow vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-text/acroread", unaffected: make_list("ge 7.0"), vulnerable: make_list("le 5.10")
)) { security_warning(0); exit(0); }
