# This script was written by Jeff Adams <jadams@netcentrics.com>
# This script is Copyright (C) 2004 Jeff Adams


if(description)
{
 script_id(12287);
 
 script_version("$Revision: 1.2 $");

 name["english"] = "IIS Download.Ject Trojan Detection";

 script_name(english:name["english"]);
 
 desc["english"] = "
Download.Ject is a Trojan that infects Microsoft IIS servers.

The Trojan's dropper sets it as the document footer for all pages 
served by IIS Web sites on the infected computer.  

See also :
http://www.microsoft.com/security/incident/download_ject.mspx

Solution : Use an Anti-Virus to clean machine. 

Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "IIS Download.Ject Trojan Detection";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Backdoors";
 script_family(english:family["english"]);
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80); 
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))
	exit(0);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig )  
	exit(0);

r = http_get_cache(item:"/", port:port);
if(r == NULL)
	exit(0);

if ( ("function sc088(n24,v8)" >< r) &&
     ("var qxco7=document.cookie" >< r) )
{
	security_hole(port);
	exit(0);
}

