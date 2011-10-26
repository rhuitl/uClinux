# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-14.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2004 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14695);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200409-14");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200409-14
(Samba: Remote printing vulnerability)


    Due to a bug in the printer_notify_info() function, authorized users could
    potentially crash the Samba server by sending improperly handled print
    change notification requests in an invalid order. Windows XP SP2 clients
    can trigger this behavior by sending a FindNextPrintChangeNotify() request
    before previously sending a FindFirstPrintChangeNotify() request.
  
Impact

    A remote authorized user could potentially crash a Samba server after
    issuing these out of sequence requests.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://samba.org/samba/history/samba-3.0.6.html
    http://www.securityfocus.com/archive/1/373619


Solution: 
    All Samba users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=net-fs/samba-3.0.6"
    # emerge ">=net-fs/samba-3.0.6"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2004 Michel Arboi");
 script_name(english: "[GLSA-200409-14] Samba: Remote printing vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Samba: Remote printing vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-fs/samba", unaffected: make_list("ge 3.0.6"), vulnerable: make_list("lt 3.0.6")
)) { security_warning(0); exit(0); }
