#
# (C) Tenable Network Security
#

 desc["english"] = "
Synopsis :

An IMAP server is running on the remote host.

Description :

An IMAP (Internet Message Access Protocol) server is
installed and running on the remote host.

Risk factor :

None";


if(description)
{
 script_id(11414);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "Get the IMAP Banner";
 
 script_name(english:name["english"]);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

 script_description(english:desc["english"]);
 summary["english"] = "Grab and display the IMAP banner";
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 family["english"] = "General";
 script_family(english:family["english"]); 

 script_dependencie("find_service.nes");
 script_require_ports("Services/imap", 143);
 exit(0);
}

include ("imap_func.inc");

port = get_kb_item("Services/imap");
if(!port) port = 143;

banner = get_imap_banner (port:port);
if(banner)
{
 report = string (desc["english"],
		"\n\nPlugin output :\n\n",
		"The remote imap server banner is :\n",
		banner);

 security_note(port:port, data:report);
}

