#
# (C) Tenable Network Security
#

if(description)
{
 script_id(14381);
 script_bugtraq_id(11055);
 script_cve_id("CVE-2004-0829");
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"9362");
 script_version ("$Revision: 1.9 $");
 name["english"] = "Samba FindNextPrintChangeNotify() Denial of Service";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote Samba server, according to its version number, is vulnerable 
to a denial of service.

An attacker may be able to crash the remote samba server by sending
a FindNextPrintChangeNotify() request without previously issuing a
FindFirstPrintChangeNoticy() call.

It is reported that Windows XP SP2 generates such requests.

Solution : upgrade to Samba 2.2.11 or 3.0.6
Risk factor : Medium";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "checks samba version";
 summary["francais"] = "vérifie la version de samba";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Denial of Service";
 script_family(english:family["english"]);
 script_dependencie("smb_nativelanman.nasl");
 script_require_keys("SMB/NativeLanManager");
 exit(0);
}

#
# The script code starts here
#

lanman = get_kb_item("SMB/NativeLanManager");
if("Samba" >< lanman)
{
 if(ereg(pattern:"Samba 2\.2\.([0-9][^0-9]*|10)$",
 	 string:lanman))security_warning(139);
 else if(ereg(pattern:"Samba 3\.0\.[0-5][^0-9]*$",
 	 string:lanman))security_warning(139);
}
