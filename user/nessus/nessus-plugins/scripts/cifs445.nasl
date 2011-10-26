#
# This script was written by Tenable Network Security
#
# This script is released under Tenable Plugins License
#

if(description)
{
 script_id(11011);
 script_version ("$Revision: 1.19 $");
 
 name["english"] = "SMB Detection";
 script_name(english:name["english"]);
 
 desc["english"] = "
This script detects wether port 445 and 139 are open and
if they are running SMB servers.

Risk factor : None";



 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for openness of port 445";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

 family["english"] = "Windows";

 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_require_ports(139, 445);
 exit(0);
}

#
# The script code starts here
#

include("smb_func.inc");

flag = 0;

if(get_port_state(445))
{
 soc = open_sock_tcp(445);
 if(soc){
 session_init(socket:soc);
 ret = smb_negotiate_protocol ();
 close(soc);
 if(ret){
	set_kb_item(name:"Services/cifs", value:445);
	set_kb_item(name:"Known/tcp/445", value:"cifs");
	security_note(port:445, data:"A CIFS server is running on this port");
	set_kb_item(name:"SMB/transport", value:445);
	flag = 1;
      }
   }
}


if(get_port_state(139))
{
  soc = open_sock_tcp(139);
  if(soc){
          session_init (socket:soc);
          called_name = netbios_name (orig:string("Nessus", rand()));
          calling_name = netbios_name (orig:NULL);

          data = called_name + raw_byte (b:0) +
                 calling_name + raw_byte (b:0);
          r = netbios_sendrecv (type:0x81, data:data);
          close(soc);
          if(r && (ord(r[0]) == 0x82 || ord(r[0]) == 0x83)) {
		set_kb_item(name:"Services/smb", value:139);
		set_kb_item(name:"Known/tcp/139", value:"smb");
		security_note(port:139, data:"An SMB server is running on this port");	
    		if(!flag)set_kb_item(name:"SMB/transport", value:139);
		}
	}
}

