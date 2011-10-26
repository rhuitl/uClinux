#
# This script is based on Thomas Reinke's qpopper2.nasl
# Modified by Scott Shebby scotts@scanalert.com
#
if(description)
{
 script_id(12279);
 script_bugtraq_id(7110);
 script_version ("$Revision: 1.7 $");

 name["english"] = "QPopper Username Information Disclosure";
 script_name(english:name["english"]);

 desc["english"]  = "
The remote server appears to be running a version of QPopper 
that is older than 4.0.6.

Versions older than 4.0.6 are vulnerable to a bug where remote 
attackers can enumerate valid usernames based on server 
responses during the authentication process.

Solution : None at this time
Risk factor : Low";
 script_description(english:desc["english"]);

 summary["english"] = "QPopper Username Information Disclosure";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);


 script_copyright(english:"This script is Copyright (C) 2004 Scott Shebby");

 family["english"] = "Misc.";

 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/pop3", 110);
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/pop3");
if(!port)port = 110;

banner = get_kb_item(string("pop3/banner/", port));
if(!banner){
    if(get_port_state(port)){
        soc = open_sock_tcp(port);
        if(!soc)exit(0);
        banner = recv_line(socket:soc, length:4096);
    }
}

if(banner){
    if(ereg(pattern:".*Qpopper.*version ([0-3]\.*|4\.0\.[0-5][^0-9]).*", string:banner, icase:TRUE)){
        security_note(port);
    }
}
