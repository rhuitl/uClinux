#
# (C) Tenable Network Security
#


 desc["english"] = "
Synopsis :

The remote printer has no password set

Description :


The remote printer has no password set. This allows anyone 
to change its IP or potentially to intercept print jobs sent
to it.

Solution : 

Telnet to this printer and set a password.

Risk factor :

High / CVSS Base Score : 8 
(AV:R/AC:L/Au:NR/C:P/A:C/I:P/B:N)";


if(description)
{
 script_id(12236);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-1999-1061");

 name["english"] = "Passwordless Lexmark Printer";
 script_name(english:name["english"]);
 


 script_description(english:desc["english"]);
 
 summary["english"] = "Notifies that the remote printer has no password";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Misc.";
 family["francais"] = "Divers";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports(9000);
 exit(0);
}

#
# The script code starts here
#
include('telnet_func.inc');
port = 9000;
if(get_port_state(port))
{
 buf = get_telnet_banner(port:port);
 if ("This session allows you to set the TCPIP parameters for your" >< buf &&
     "Set IP address Options" >< buf  )
     security_hole(port:port, data:desc["english"] + '\n\nPlugin output :\n\n' + buf);
}
