# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200512-05.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20314);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200512-05");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200512-05
(Xmail: Privilege escalation through sendmail)


    iDEFENSE reported that the AddressFromAtPtr function in the
    sendmail program fails to check bounds on arguments passed from other
    functions, and as a result an exploitable stack overflow condition
    occurs when specifying the "-t" command line option.
  
Impact

    A local attacker can make a malicious call to sendmail,
    potentially resulting in code execution with elevated privileges.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2943
    http://www.idefense.com/application/poi/display?id=321&type=vulnerabilities&flashstatus=true


Solution: 
    All Xmail users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-mta/xmail-1.22"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200512-05] Xmail: Privilege escalation through sendmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Xmail: Privilege escalation through sendmail');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "mail-mta/xmail", unaffected: make_list("ge 1.22"), vulnerable: make_list("lt 1.22")
)) { security_hole(0); exit(0); }
