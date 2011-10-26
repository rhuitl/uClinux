# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200507-21.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19323);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200507-21");
 script_cve_id("CVE-2005-2335");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200507-21
(fetchmail: Buffer Overflow)


    fetchmail does not properly validate UIDs coming from a POP3 mail
    server. The UID is placed in a fixed length buffer on the stack, which
    can be overflown.
  
Impact

    Very long UIDs returned from a malicious or compromised POP3
    server can cause fetchmail to crash, resulting in a Denial of Service,
    or allow arbitrary code to be placed on the stack.
  
Workaround

    There are no known workarounds at this time.
  
References:
    http://fetchmail.berlios.de/fetchmail-SA-2005-01.txt
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2335


Solution: 
    All fetchmail users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-mail/fetchmail-6.2.5.2"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200507-21] fetchmail: Buffer Overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'fetchmail: Buffer Overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-mail/fetchmail", unaffected: make_list("ge 6.2.5.2"), vulnerable: make_list("lt 6.2.5.2")
)) { security_warning(0); exit(0); }
