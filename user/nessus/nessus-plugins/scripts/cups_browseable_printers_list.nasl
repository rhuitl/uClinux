#
# (C) Tenable Network Security
#


if(description)
{
 script_id(11754);
 script_version("$Revision: 1.3 $");
 
 
 name["english"] = "List of printers is available through CUPS";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running CUPS (Common Unix Printing System).

An attacker may connect to this port and browse /printers
to obtain the list of printers this host can access.

This is particulary useful as some attacks require an attacker
to provide a valid printer name.

Solution : Filter incoming traffic to this port 
Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Obtains the list of printers on the remote host";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Misc.";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www",631);
 script_require_keys("www/cups");
 exit(0);
}

#

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


ports = add_port_in_list(list:get_kb_list("Services/www"), port:631);

foreach port (ports)
{
 req = http_get(item:"/printers", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if("CUPS" >< res )
 {
 default = egrep(pattern:"Default Destination:", string:res);
 if( default )
 {
 default = ereg_replace(pattern:".*Default Destination:</B> <.*>(.*)</A>",
 			replace:"\1",
			string:default);
 
 
 printers = split(egrep(pattern:"Description:.*<BR>", string:res));
 ps = NULL;
 foreach p (printers)
 {
  ps += ereg_replace(pattern:".*Description: (.*)<BR>", string:p,
 			 replace:"  . \1") ;
 
 }	
  	
 report = "The remote host is running CUPS (Common Unix Printing System).

An attacker may connect to this port and browse /printers
to obtain the list of printers this host can access.

This is particulary useful as some attacks require an attacker
to provide a valid printer name.

The following list of printers has been obtained :
 
" + ps + "
The remote host default printer is " + default + "

Solution : Filter incoming traffic to this port 
Risk factor : Low";
 security_warning(port:port, data:report);
 exit(0);
 }
 }
}
