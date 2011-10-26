
if(description)
{
 script_id(12053);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "Host FQDN";
 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin writes the host FQDN as it could be resolved in the report. 
There is no security issue associated to it.

Risk factor : None";


 script_description(english:desc["english"]);
 
 summary["english"] = "Performs a name resolution";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "General";
 script_family(english:family["english"]);
 exit(0);
}


if ( get_host_name() != get_host_ip() )
{
 security_note(port:0, data:get_host_ip() + " resolves as " + get_host_name() + ".");
}
