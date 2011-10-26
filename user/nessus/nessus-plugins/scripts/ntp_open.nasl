#
# This script was written by David Lodge
#
# See the Nessus Scripts License for details
#
# Changes by rd:
# - recv() only receives the first two bytes of data (instead of 1024)
# - replaced ord(result[0]) == 0x1E by ord(result[0]) & 0x1E (binary AND)

if(description)
{
 script_id(10884);
 script_version("$Revision: 1.12 $");
 name["english"] = "NTP read variables";
 script_name(english:name["english"]);
 
 desc["english"] = "
An NTP (Network Time Protocol) server is listening on this port.

Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "NTP allows query of variables";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 David Lodge");
 family["english"] = "General";
 script_family(english:family["english"]);

 exit(0);
}

#
# The script code starts here
#
#

function ntp_read_list()
{
    data = raw_string(0x16, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00);
    soc = open_sock_udp(123);
    send(socket:soc, data:data);
    r = recv(socket:soc, length:4096);
    close(soc);

    if (! r) return(NULL);

    p = strstr(r, "version=");
    if (! p) p = strstr(r, "processor=");
    if (! p) p = strstr(r, "system=");
    p = ereg_replace(string:p, pattern:raw_string(0x22), replace:"'");

    if (p) return(p);
    return(NULL);
}


function ntp_installed()
{
data = raw_string(0xDB, 0x00, 0x04, 0xFA, 0x00, 0x01,
    		  0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0xBE, 0x78, 0x2F, 0x1D, 0x19, 0xBA,
		  0x00, 0x00);

soc = open_sock_udp(123);
send(socket:soc, data:data);
r = recv(socket:soc, length:4096);
close(soc);

if(strlen(r) > 10)
 {
 return(r);
 }
return(NULL);
}



# find out whether we can open the port

if( !(get_udp_port_state(123)) ) exit(0);



r = ntp_installed();
if(r)
   {
      set_kb_item(name:"NTP/Running", value:TRUE);
      list = ntp_read_list();
      if(!list)security_note(port:123, protocol:"udp");
      else
       {
       if ("system" >< list )
        {
         s = egrep(pattern:"system=", string:list);
	 os = ereg_replace(string:s, pattern:".*system='([^']*)'.*", replace:"\1");
         set_kb_item(name:"Host/OS/ntp", value:os);
        }
       if ("processor" >< list )
        {
         s = egrep(pattern:"processor=", string:list);
	 os = ereg_replace(string:s, pattern:".*processor='([^']*)'.*", replace:"\1");
         set_kb_item(name:"Host/processor/ntp", value:os);
        }
      report = "It is possible to determine a lot of information about the remote host 
by querying the NTP (Network Time Protocol) variables - these include 
OS descriptor, and time settings.

It was possible to gather the following information from the remote NTP host : 

" + list + "


Quickfix: Set NTP to restrict default access to ignore all info packets:
	restrict default ignore

Risk factor : Low";
      security_note(port:123, protocol:"udp", data:report);
    }
  }

 
