# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200412-12.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15993);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200412-12");
 script_cve_id("CVE-2004-1152");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200412-12
(Adobe Acrobat Reader: Buffer overflow vulnerability)


    A buffer overflow has been discovered in the email processing of
    Adobe Acrobat Reader. This flaw exists in the mailListIsPdf function,
    which checks if the input file is an email message containing a PDF
    file.
  
Impact

    A remote attacker could send the victim a specially-crafted email
    and PDF attachment, which would trigger the buffer overflow and
    possibly lead to the execution of arbitrary code with the permissions
    of the user running Adobe Acrobat Reader.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1152
    http://www.adobe.com/support/techdocs/331153.html


Solution: 
    All Adobe Acrobat Reader users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/acroread-5.10"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200412-12] Adobe Acrobat Reader: Buffer overflow vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Adobe Acrobat Reader: Buffer overflow vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-text/acroread", unaffected: make_list("ge 5.10"), vulnerable: make_list("lt 5.10")
)) { security_warning(0); exit(0); }
