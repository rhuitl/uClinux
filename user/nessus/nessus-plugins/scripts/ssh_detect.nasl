#
# This script was originally written by Noam Rathaus <noamr@securiteam.com>, but was entirely
# rewritten by Tenable to use the ssh_func.inc API
#
# 
#
#

if(description)
{
 script_id(10267);
 script_version ("$Revision: 1.25 $");
 
 name["english"] = "SSH Server type and version";
 script_name(english:name["english"]);
 
 desc["english"] = "
This script displays the version and supported protocols of the remote SSH server";

 script_description(english:desc["english"]);
 
 summary["english"] = "SSH Server type and version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) Tenable Network Security");
 family["english"] = "General";
 script_family(english:family["english"]);
 script_require_ports("Services/ssh", 22);
 script_dependencies("find_service.nes", "find_service2.nasl", "external_svc_ident.nasl");
 exit(0);
}


#
# The script code starts here
#
include("misc_func.inc");
include("ssh_func.inc");

port = get_kb_item("Services/ssh");

if (!port) port = 22;
if (get_port_state(port))
{
 soc = open_sock_tcp(port);
 if ( ! soc ) exit(0);
 if ( defined_func("bn_random") ) 
 {
 ssh_login (socket:soc, login:"n3ssus", password:"n3ssus", pub:NULL, priv:NULL, passphrase:NULL);

 version = get_ssh_server_version ();
 banner = get_ssh_banner ();
 supported = get_ssh_supported_authentication ();
 }
 else 
 {
 version = recv_line(socket:soc, length:4096);
 if ( !ereg(pattern:"^SSH-", string:version ) ) exit(0);
 }

 if (version)
 {
   set_kb_item(name:"SSH/banner/" + port, value:version);
   text = "Remote SSH version : " + version + '\n\n';

   if (supported)
   {
     set_kb_item(name:"SSH/supportedauth/" + port, value:supported);
     text += 'Remote SSH supported authentication : ' + supported + '\n\n';
   }
   
   if (banner)
   {
     set_kb_item(name:"SSH/textbanner/" + port, value:banner);
     text += 'Remote SSH banner : \n' + banner + '\n\n';
   }

   security_note(port:port, data:text);
   register_service(port:port, proto: "ssh");   
 }
}
 
