#
# Copyright (C) 2004 Tenable Network Security
#
if(description)
{
 script_id(12114);
 script_bugtraq_id(1389, 4025, 4950, 9513, 9514, 9752);
 script_version("$Revision: 1.9 $");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-A-5003");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-A-0003");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-A-0004");
 script_cve_id("CVE-2002-0237", "CVE-2000-0562", "CVE-2002-0956", "CVE-2002-0957", "CVE-2004-0193");

 name["english"] = "ISS BlackICE Vulnerable versions";

 script_name(english:name["english"]);


 desc["english"] = "
ISS BlackICE is a personal Firewall/IDS for windows Desktops.
Several remote holes have been found in the product.  An attacker,
exploiting these flaws, would be able to either stop the remote
firewall/IDS service or execute code on the target machine.  

According to the remote version number, the remote host is vulnerable
to at least one remote overflows.

Solution : Upgrade to the newest version of BlackICE
Risk factor : High";



 script_description(english:desc["english"]);

 summary["english"] = "ISS BlackICE Vulnerable version detection";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);

 script_dependencies("blackice_configs.nasl");
 script_require_keys("SMB/BlackICE/Version");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
myread = get_kb_item("SMB/BlackICE/Version");
if ( ! myread ) exit(0);


# what does the logfile format look like:
# ---------- BLACKD.LOG
# [25]Fri, 19 Mar 2004 09:58:20: BlackICE Product Version :               7.0.ebf

if (strstr(myread, "BlackICE Product Version"))  {
    # all versions 7.0 eba through ebh and 3.6 ebr through ecb 
    if (egrep(string:myread, pattern:"BlackICE Product Version.*(7\.0\.eb[a-h]|3\.6\.e(b[r-z]|c[ab]))")) {
        # do a warning for smb bug
        mywarning = string("ISS BlackICE is a personal Firewall/IDS for windows Desktops.
Several remote holes have been found in the product.  An attacker,
exploiting these flaws, would be able to either stop the remote
firewall/IDS service or execute code on the target machine.

According to the remote version number, the remote host is vulnerable
to a bug wherein a malformed SMB packet will allow the attacker to execute
arbitrary code on the target system.


Solution : Upgrade the BlackICE to a non-vulnerable version.
See also : http://www.eeye.com/html/Research/Advisories/AD20040226.html
Risk factor : High");
    port = kb_smb_transport();
    if (!port) port = 139;
    security_hole(port:port, data:mywarning);
    }


    # all versions prior to 7.0.ebl and 3.6.ecf
    if ( (egrep(string:myread, pattern:"BlackICE Product Version.*[0-6]\.[0-9]\.[a-z][a-z][a-z]")) ||
    (egrep(string:myread, pattern:"BlackICE Product Version.*7\.0\.([a-d][a-z][a-z]|e(a[a-z]|b[a-h]))")) ) {
                mywarning = string("ISS BlackICE is a personal Firewall/IDS for windows Desktops.
Several remote holes have been found in the product.  An attacker,
exploiting these flaws, would be able to either stop the remote
firewall/IDS service or execute code on the target machine.

According to the remote version number, the remote host is vulnerable
to a bug wherein a malformed ICQ packet will allow the attacker to execute
arbitrary code on the target system.

Solution : Upgrade the BlackICE to a non-vulnerable version.
See also : http://www.eeye.com/html/Research/Advisories/AD20040318.html  
Risk factor : High");
    port = kb_smb_transport();
    if (!port) port = 139;
    security_hole(port:port, data:mywarning);
    }


    # only certain versions which have a default config issue
    # VULN VERSION:
    # 7.0 eb[j-m]
    # 3.6 ec[d-g]
    # 3.6 cc[d-g]

    if (egrep(string:myread, pattern:"BlackICE Product Version.*(7\.0\.eb[j-m]|3\.6\.(ec[d-g]|cc[d-g]))")) {
        #warning for misconfiguration
        mywarning = string("ISS BlackICE is a personal Firewall/IDS for windows Desktops.
        The BlackIce version found has a misconfiguration in the default settings that changed the
default blocking and reporting behavior and may affect the level of protection
provided by the product.

Solution : Upgrade the BlackICE to a non-vulnerable version.( 7.0 ebn, 3.6 ech, 3.6 cch )
Risk factor : High");
    port = kb_smb_transport();
    if (!port) port = 139;
    security_hole(port:port, data:mywarning);
    }

}

