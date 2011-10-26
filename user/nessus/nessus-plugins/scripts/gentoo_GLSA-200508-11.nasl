# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200508-11.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19484);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2005-t-0033");
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200508-11");
 script_cve_id("CVE-2005-2470");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200508-11
(Adobe Reader: Buffer Overflow)


    A buffer overflow has been reported within a core application
    plug-in, which is part of Adobe Reader.
  
Impact

    An attacker may create a specially-crafted PDF file, enticing a
    user to open it. This could trigger a buffer overflow as the file is
    being loaded, resulting in the execution of arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2470
    http://www.adobe.com/support/techdocs/321644.html


Solution: 
    All Adobe Reader users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/acroread-7.0.1.1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200508-11] Adobe Reader: Buffer Overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Adobe Reader: Buffer Overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-text/acroread", unaffected: make_list("ge 7.0.1.1"), vulnerable: make_list("lt 7.0.1.1")
)) { security_warning(0); exit(0); }
