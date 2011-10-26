# -*- Fundamental -*-
#
# (C) Tenable Network Security
#
#


function get_pop3_banner (port)
{
  local_var sb, banner, soc;
  
  sb = string("pop3/banner/", port);
  banner = get_kb_item(sb);
  if(banner) return (banner);
  if ( get_kb_item("pop3/" + port + "/broken") ) 
	return NULL;

  if(! get_port_state(port)) return (0);
  soc = open_sock_tcp(port);
  if (! soc) {
	set_kb_item(name:"pop3/" + port + "/broken", value:TRUE);
	return NULL;
	}
  banner =  recv_line(socket: soc, length:4096);
  close(soc);
  if(! banner ) {
	set_kb_item(name:"pop3/" + port + "/broken", value:TRUE);
	return NULL;
	}
	
  
  if ( defined_func("replace_kb_item") )
  	replace_kb_item(name: sb, value: banner);
  else
  	set_kb_item(name: sb, value: banner);
  return(banner);
}

