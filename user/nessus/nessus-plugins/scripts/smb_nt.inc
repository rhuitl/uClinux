# -*- Fundamental -*-
#
# (C) Tenable Network Security
#
# smb_nt.inc 
# $Revision: 1.84 $
#

include ('crypto_func.inc');

global_var multiplex_id, g_mhi, g_mlo;

multiplex_id = rand();
g_mhi = multiplex_id / 256;
g_mlo = multiplex_id % 256;

function raw_byte (b)
{
 return raw_string (b);
}

function raw_dword (d)
{
 return raw_string ( (d)     & 255,
                     (d>>8)  & 255,
                     (d>>16) & 255,
                     (d>>24) & 255 );
}


function get_dword (blob, pos)
{
 if (pos > (strlen (blob) - 4))
   return NULL;

 return ( ord(blob[pos]) + 
          (ord(blob[pos+1]) << 8) +
          (ord(blob[pos+2]) << 16) +
          (ord(blob[pos+3]) << 24) );
}




function kb_smb_name()
{
 return string(get_kb_item("SMB/name"));
}

function kb_smb_domain()
{
 return string(get_kb_item("SMB/domain"));
}

function kb_smb_login()
{
 return string(get_kb_item("SMB/login"));
}

function kb_smb_password()
{
 return string(get_kb_item("SMB/password"));
}

function kb_smb_transport()
{
 local_var r;
 r = get_kb_item("SMB/transport");
 if ( r ) return int(r);
 else return 445;
}


#-----------------------------------------------------------------#
# Reads a SMB packet						  #
#-----------------------------------------------------------------#
function smb_recv(socket, length)
{
   local_var header, len, trailer;

   header = recv(socket:socket, length:4, min:4);
   if (strlen(header) < 4)return(NULL);
   len = 256 * ord(header[2]);
   len += ord(header[3]);
   if (len == 0)return(header);
   trailer = recv(socket:socket, length:len, min:len);
   if(strlen(trailer) < len )return(NULL);
   return strcat(header, trailer);
}

#-----------------------------------------------------------------#
# Encode name and service to the netbios network format           #
#-----------------------------------------------------------------#
function netbios_encode(data,service)
{
 local_var tmpdata, ret;

 ret = "";
 tmpdata = data; 

 while (strlen(tmpdata) < 15)
 {
   tmpdata += " ";
 }

 tmpdata += raw_string(service);

 for(i=0;i<16;i=i+1)
 {
   o = ord(tmpdata[i]);
   odiv = o/16;
   odiv = odiv + ord("A");
   omod = o%16;
   omod = omod + ord("A");
   c = raw_string(odiv, omod);

   ret = ret+c;
 }

 return(ret); 
}

#-----------------------------------------------------------------#
# Convert a netbios name to the netbios network format            #
#-----------------------------------------------------------------#
function netbios_name(orig)
{
 return netbios_encode(data:orig, service:0x20); 
}

#--------------------------------------------------------------#
# Returns the netbios name of a redirector                     #
#--------------------------------------------------------------#

function netbios_redirector_name()
{
 ret = crap(data:"CA", length:30);
 ret = ret+"AA";
 return(ret); 
}

#-------------------------------------------------------------#
# return a 28 + strlen(data) + (odd(data)?0:1) long string    #
#-------------------------------------------------------------#
function unicode(data)
{
 len = strlen(data);
 ret = raw_string(ord(data[0]));
 
 for(i=1;i<len;i=i+1)
 {
  ret = string(ret, raw_string(0, ord(data[i])));
 }
 
 
 if(!(len & 1)){even = 1;}
 else even = 0;
 

 for(i=0;i<7;i=i+1)
  ret = ret + raw_string(0);
  
  
 if(even) ret = ret + raw_string(0x00, 0x00);
 
  
 return(ret);
}




#----------------------------------------------------------#
# Request a new SMB session                                #
#----------------------------------------------------------#
function smb_session_request(soc, remote, transport)
{
 if ( transport )
	trp = transport;
 else 
 	trp = kb_smb_transport();

 # We don't need to request a session when talking on top of
 # port 445
 if(trp == 445)
  return(TRUE);
  
 nb_remote = netbios_name(orig:remote);
 nb_local  = netbios_redirector_name();
 
 session_request = raw_string(0x81, 0x00, 0x00, 0x44) + 
		  raw_string(0x20) + 
		  nb_remote +
		  raw_string(0x00, 0x20)    + 
		  nb_local  + 
		  raw_string(0x00);

 send(socket:soc, data:session_request);
 r = smb_recv(socket:soc, length:4000);
 if(ord(r[0])==0x82)return(r);
 else return(FALSE);
}

#------------------------------------------------------------#
# Extract the UID from the result of smb_session_setup()     #
#------------------------------------------------------------#

function session_extract_uid(reply)
{
 low = ord(reply[32]);
 high = ord(reply[33]);
 ret = high * 256;
 ret = ret + low;
 return(ret);
}



#-----------------------------------------------------------#
# Negociate (pseudo-negociate actually) the protocol        #
# of the session                                            #
#-----------------------------------------------------------#

function smb_neg_prot_cleartext(soc)
{
 neg_prot = raw_string
   	(
	 0x00,0x00,
	 0x00, 0x89, 0xFF, 0x53, 0x4D, 0x42, 0x72, 0x00,
	 0x00, 0x00, 0x00, 0x18, 0x01, 0x20, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00,
	 g_mlo, g_mhi, 0x00, 0x66, 0x00, 0x02, 0x50, 0x43,
	 0x20, 0x4E, 0x45, 0x54, 0x57, 0x4F, 0x52, 0x4B,
	 0x20, 0x50, 0x52, 0x4F, 0x47, 0x52, 0x41, 0x4D,
	 0x20, 0x31, 0x2E, 0x30, 0x00, 0x02, 0x4D, 0x49,
	 0x43, 0x52, 0x4F, 0x53, 0x4F, 0x46, 0x54, 0x20,
	 0x4E, 0x45, 0x54, 0x57, 0x4F, 0x52, 0x4B, 0x53,
	 0x20, 0x31, 0x2E, 0x30, 0x33, 0x00, 0x02, 0x4D,
	 0x49, 0x43, 0x52, 0x4F, 0x53, 0x4F, 0x46, 0x54,
	 0x20, 0x4E, 0x45, 0x54, 0x57, 0x4F, 0x52, 0x4B,
	 0x53, 0x20, 0x33, 0x2e, 0x30, 0x00, 0x02, 0x4c,
	 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x31, 0x2e, 0x30,
	 0x00, 0x02, 0x4c, 0x4d, 0x31, 0x2e, 0x32, 0x58,
	 0x30, 0x30, 0x32, 0x00, 0x02, 0x53, 0x61, 0x6d,
	 0x62, 0x61, 0x00
	 );
	 
 send(socket:soc, data:neg_prot);
 r = smb_recv(socket:soc, length:4000);
 if(strlen(r) < 10)return(FALSE);
 if(ord(r[9])==0)return(r);
 else return(FALSE);
}



function smb_neg_prot_NTLMv1(soc)
{
 local_var neg_prot, r;
 
 neg_prot = raw_string
   	(
	 0x00, 0x00, 0x00, 0xA4, 0xFF, 0x53,
	 0x4D, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00, 0x08,
	 0x01, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x4D, 0x0B, 0x00, 0x00, g_mlo, g_mhi, 0x00, 0x81,
	 0x00, 0x02
	 ) + "PC NETWORK PROGRAM 1.0" + raw_string(0x00, 0x02) +
	 "MICROSOFT NETWORKS 1.03" + raw_string(0x00, 0x02) + 
	 "MICROSOFT NETWORKS 3.0"  + raw_string(0x00, 0x02) + 
	 "LANMAN1.0" + raw_string(0x00, 0x02) + 
	 "LM1.2X002" + raw_string(0x00, 0x02) + 
	 "Samba" +     raw_string(0x00, 0x02) +
	 "NT LANMAN 1.0" + raw_string(0x00, 0x02) +
	 "NT LM 0.12" + raw_string(0x00);
	 
	 
 send(socket:soc, data:neg_prot);
 r = smb_recv(socket:soc, length:4000);
 if(strlen(r) < 38)return(NULL);
 if(ord(r[9])==0)return(string(r));
 else return(NULL);
}

function smb_neg_prot(soc)
{
 if(defined_func("MD5"))
   return smb_neg_prot_NTLMv1(soc:soc);
 else 
  return smb_neg_prot_cleartext(soc:soc);
}


function smb_neg_prot_value(prot)
{
 return(ord(prot[37]));
}

function smb_neg_prot_cs(prot)
{
 if(smb_neg_prot_value(prot:prot) < 7)
  return NULL;
  
 return substr(prot, 73, 73 + 7);
}
 
function smb_neg_prot_domain(prot)
{
 local_var i, ret;
 ret = NULL;
 for(i=81;i<strlen(prot);i+=2)
 {
  if(ord(prot[i]) == 0) break;
  else ret += prot[i];
 }
 return ret;
}

#------------------------------------------------------#
# Set up a session                                     #
#------------------------------------------------------#
function smb_session_setup_cleartext(soc, login, password, domain)
{
  local_var extra, native_os, native_lanmanager, len, bcc;
  local_var len_hi, len_lo, bcc_hi_n, bcc_lo;
  local_var pass_len_hi, pass_len_lo;
  extra = 0;
  native_os = "Unix";
  native_lanmanager = "Nessus";
  if(!domain)domain = "MYGROUP";

  if(domain) extra = 3+ strlen(domain) + strlen(native_os) + strlen(native_lanmanager);
  else extra = strlen(native_os) + strlen(native_lanmanager) + 2;


  
  len = strlen(login) + strlen(password) + 57 + extra;
  bcc = 2 + strlen(login) + strlen(password) + extra;
  
  len_hi = len / 256;
  len_low = len % 256;
  
  bcc_hi = bcc / 256;
  bcc_lo = bcc % 256;
  
  pass_len = strlen(password) + 1 ;
  pass_len_hi = pass_len / 256;
  pass_len_lo = pass_len % 256;

  #if (typeof(login) == "int")    display("HORROR! login=",    login, "\n");
  #if (typeof(password) == "int") display("HORROR! password=", password, "\n");
  if (! login) login="";
  if (! password) password="";
  
  st = raw_string(0x00,0x00,
    	  len_hi, len_low, 0xFF, 0x53, 0x4D, 0x42, 0x73, 0x00,
	  0x00, 0x00, 0x00, 0x18, 0x01, 0x20, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00,
	  0x00, 0x00, 0x0A, 0xFF, 0x00, 0x00, 0x00, 0x04,
	  0x11, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x00, pass_len_lo,  pass_len_hi, 0x00, 0x00, 0x00, 0x00, bcc_lo,
	  bcc_hi) + password + raw_string(0) + login + raw_string(0x00);
	  
  if(domain)
  	st = st + domain + raw_string(0x00);	
	
  st = st + native_os + raw_string(0x00) + native_lanmanager + raw_string(0x00);
  	  
  send(socket:soc, data:st);
  r = smb_recv(socket:soc, length:1024); 
  if(strlen(r) < 9)return(NULL);
  if(ord(r[9])==0)return(r);
  else return(NULL);
}	   


function smb_session_setup_NTLMvN(soc, login, password, domain, cs, version)
{
  local_var extra, native_os, native_lanmanager, len, bcc;
  local_var len_hi, len_lo, bcc_hi_n, bcc_lo;
  local_var plen;
  
  local_var response, pass, i, log, dom, ipass, spass;

  pass = log = dom = NULL;
  for (i=0;i < strlen(password);i++)
    pass += password[i] + raw_string(0x00);

  for (i=0;i < strlen(login);i++)
    log += login[i] + raw_string(0x00);

  for (i=0;i < strlen(domain);i++)
    dom += domain[i] + raw_string(0x00);

  ipass = spass = NULL;

  if(version == 1)
  {
  	if(login && password)
  	{
  	 response = NTLM_Response (password:pass, challenge:cs);
  	 if (!isnull(response))
           ipass = response[0];
        }
  }
  else 
  {
    	if(login && password)
	{
         response = LMv2_Response (password:pass, login:log, domain:dom, challenge:cs);
  	 if (!isnull(response))
           ipass = response[0];
	}
  }
  
  
  extra = 0;
  native_os = "Unix";
  native_lanmanager = "Nessus";

  extra = 3 + strlen(domain) + strlen(native_os) + strlen(native_lanmanager);
  
  
  len = strlen(login) + strlen(ipass) + strlen(spass) + 62 + extra;
  bcc = 1 + strlen(login) + strlen(ipass) + strlen(spass) + extra;
  
  
  len_hi = len / 256;
  len_low = len % 256;
  
  bcc_hi = bcc / 256;
  bcc_lo = bcc % 256;
  
  
  st = raw_string(0x00,0x00,
    	  len_hi, len_low, 0xFF, 0x53,
	  0x4D, 0x42, 0x73, 0x00, 0x00, 0x00, 0x00, 0x08,
	  0x01, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x28, 0x00, 0x00, g_mlo, g_mhi, 0x0D, 0xFF,
	  0x00, 0x00, 0x00, 0x00, 0x44, 0x02, 0x00, 0xA0,
	  0xF5, 0x00, 0x00, 0x00, 0x00, strlen(ipass) % 256, 0x00, strlen(spass) % 256,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x00, bcc_lo, bcc_hi) + ipass + spass + login + 
	  raw_string(0);
	  
  st += domain + raw_string(0x00);	
	
  st += native_os + raw_string(0x00) + native_lanmanager + raw_string(0x00);
  	  
  send(socket:soc, data:st);
  r = smb_recv(socket:soc, length:1024); 
  if(strlen(r) < 9)return(FALSE);
  if(ord(r[9])==0)return(r);
  else return(FALSE);
}	   


function smb_session_setup(soc, login, password, domain, prot)
{
 local_var ct, ret, ntlmv1;
 
 ct = get_kb_item("SMB/dont_send_in_cleartext");
 ntlmv1 = get_kb_item("SMB/dont_send_ntlmv1");
 
 if( smb_neg_prot_value(prot:prot) < 7 )
  {
  if(ct == "yes") return NULL;
  else return smb_session_setup_cleartext(soc:soc, login:login, password:password, domain:domain);
  }
 else
  {
  ret = smb_session_setup_NTLMvN(soc:soc, login:login, password:password, domain:domain, cs:smb_neg_prot_cs(prot:prot), version:2);
  if(!ret && !ntlmv1) ret = smb_session_setup_NTLMvN(soc:soc, login:login, password:password, domain:domain, cs:smb_neg_prot_cs(prot:prot), version:1);
  return ret;
  }
}



#------------------------------------------------------#
# connection to a remote share                         #
#------------------------------------------------------#		
#
# connection to the remote IPC share
#		
function smb_tconx(soc,name,uid, share)
{

 high = uid / 256;
 low = uid % 256;
 len = 48 + strlen(name) + strlen(share) + 6;
 ulen = 5 + strlen(name) + strlen(share) + 6;
 
 
 
 req = raw_string(0x00, 0x00,
 		  0x00, len, 0xFF, 0x53, 0x4D, 0x42, 0x75, 0x00,
		  0x00, 0x00, 0x00, 0x18, 0x01, 0x20, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x28, low, high,
		  0x00, 0x00, 0x04, 0xFF, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x01, 0x00, ulen, 0x00, 0x00, 0x5C, 0x5C) +
	name + 
	raw_string(0x5C) + share +raw_string(0x00) +
	"?????"  + raw_string(0x00);
 send(socket:soc, data:req);
 r = smb_recv(socket:soc, length:1024);
 if(strlen(r) < 10)return(FALSE);
 if(ord(r[9])==0)return(r);
 else return(FALSE);		   	 

}

#------------------------------------------------------#
# Extract the TID from the result of smb_tconx()       #
#------------------------------------------------------#
function tconx_extract_tid(reply)
{
 if(strlen(reply) < 30) return(FALSE);
 low = ord(reply[28]);
 high = ord(reply[29]);
 ret = high * 256;
 ret = ret + low;
 return(ret);
}


#--------------------------------------------------------#
# Request the creation of a pipe to name. Name must      #
# contain '\'.                                           #
#--------------------------------------------------------#
function smbntcreatex(soc, uid, tid, name, always_return_blob)
{
 tid_high = tid / 256;
 tid_low  = tid % 256;
 
 uid_high = uid / 256;
 uid_low  = uid % 256;
 
  req = raw_string(0xFF, 0x53, 0x4D, 0x42, 0xA2, 0x00,
		   0x00, 0x00, 0x00, 0x18, 0x03, 0x00, 0x50, 0x81,
		   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		   0x00, 0x00, tid_low, tid_high, 0x00, 0x28, uid_low, uid_high,
		   g_mlo, g_mhi, 0x18, 0xFF, 0x00, 0x00, 0x00, 0x00,
		   0x07, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00,
		   0x00, 0x00, 0x9F, 0x01, 0x02, 0x00, 0x00, 0x00,
		   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		   0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00,
		   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
		   0x00, 0x00, 0x00, (strlen(name)+1) % 256, 0x00)
	+ name + raw_string (0x00);

 req = raw_string(0x00, 0x00, 0x00, (strlen(req)%256)) + req;

 send(socket:soc, data:req);
 r = smb_recv(socket:soc, length:4000);
 if ( always_return_blob ) return r;
 if(strlen(r) < 10)return(FALSE);
 if(ord(r[9])==0x00)return(r);
 else return(FALSE);
}


#--------------------------------------------------------#
# Extract the ID of our pipe from the result             #
# of smbntcreatex()                                      #
#--------------------------------------------------------#

function smbntcreatex_extract_pipe(reply)
{
 if(strlen(reply) < 44) return(FALSE);
 low = ord(reply[42]);
 high = ord(reply[43]);
 
 ret = high * 256;
 ret = ret + low;
 return(ret);
}



#---------------------------------------------------------#
# Determines whether the registry is accessible           #
#---------------------------------------------------------#
		
function pipe_accessible_registry(soc, uid, tid, pipe)
{
 tid_low = tid % 256;
 tid_high = tid / 256;
 uid_low = uid % 256;
 uid_high = uid / 256;
 pipe_low = pipe % 256;
 pipe_high = pipe / 256;
 
 req = raw_string(0x00, 0x00,
 		  0x00, 0x94, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
		  0x00, 0x00, 0x00, 0x18, 0x03, 0x00, 0x1B, 0x81,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, tid_low, tid_high, 0x00, 0x28, uid_low, uid_high,
		  g_mlo, g_mhi, 0x10, 0x00, 0x00, 0x48, 0x00, 0x00,
		  0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4C,
		  0x00, 0x48, 0x00, 0x4C, 0x00, 0x02, 0x00, 0x26,
		  0x00, pipe_low, pipe_high, 0x51, 0x00, 0x5C, 0x50, 0x49,
		  0x50, 0x45, 0x5C, 0x00, 0x00, 0x00, 0x05, 0x00,
		  0x0B, 0x00, 0x10, 0x00, 0x00, 0x00, 0x48, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x16,
		  0x30, 0x16, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0xd0,
		  0x8c, 0x33, 0x44, 0x22, 0xF1, 0x31, 0xAA, 0xAA,
		  0x90, 0x00, 0x38, 0x00, 0x10, 0x03, 0x01, 0x00,
		  0x00, 0x00, 0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C,
		  0xc9, 0x11, 0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10,
		  0x48, 0x60, 0x02, 0x00, 0x00, 0x00);	  
 send(socket:soc, data:req);
 r = smb_recv(socket:soc, length:4096);
 if(strlen(r) < 10)return(FALSE);
 if(ord(r[9])==0)return(r);
 else return(FALSE);
}


#----------------------------------------------------------#
# RegOpenHKLM()                                            #
#----------------------------------------------------------#

function registry_open_hklm(soc, uid, tid, pipe)
{
 local_var req, tid_low, tid_high, uid_low, uid_high, pipe_low, pipe_high, r;

 tid_low = tid % 256;
 tid_high = tid / 256;
 uid_low = uid % 256;
 uid_high = uid / 256;
 pipe_low = pipe % 256;
 pipe_high = pipe / 256;
 
 req = raw_string(0x00, 0x00,
 		  0x00, 0x78, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
		  0x00, 0x00, 0x00, 0x18, 0x03, 0x80, 0x1D, 0x83,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, tid_low, tid_high, 0x00, 0x28, uid_low, uid_high,
		  g_mlo, g_mhi, 0x10, 0x00, 0x00, 0x24, 0x00, 0x00,
		  0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54,
		  0x00, 0x24, 0x00, 0x54, 0x00, 0x02, 0x00, 0x26,
		  0x00, pipe_low, pipe_high, 0x35, 0x00, 0x00, 0x5c, 0x00,
		  0x50, 0x00, 0x49, 0x00, 0x50, 0x00, 0x45, 0x00,
		  0x5C, 0x00, 0x00, 0x00, 0x00, 0x5c, 0x05, 0x00,
		  0x00, 0x03, 0x10, 0x00, 0x00, 0x00, 0x24, 0x00,
		  0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0C, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x10, 0xFF,
		  0x12, 0x00, 0x30, 0x39, 0x01, 0x00, 0x00, 0x00,
		  0x00, 0x02);
		  

 send(socket:soc, data:req);
 r = smb_recv(socket:soc, length:4096);
 if(strlen(r) < 10)return(FALSE);
 if(ord(r[9])==0)return(r);
 else return(FALSE);
}

#----------------------------------------------------------#
# RegOpenHKU()                                             #
#----------------------------------------------------------#
function registry_open_hku(soc, uid, tid, pipe)
{
 local_var req, tid_low, tid_high, uid_low, uid_high, pipe_low, pipe_high, r;

 tid_low = tid % 256;
 tid_high = tid / 256;
 uid_low = uid % 256;
 uid_high = uid / 256;
 pipe_low = pipe % 256;
 pipe_high = pipe / 256;
 
 req = raw_string(0x00, 0x00,
 		  0x00, 0x78, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
		  0x00, 0x00, 0x00, 0x18, 0x03, 0x80, 0x1D, 0x83,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, tid_low, tid_high, 0x00, 0x28, uid_low, uid_high,
		  g_mlo, g_mhi, 0x10, 0x00, 0x00, 0x24, 0x00, 0x00,
		  0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54,
		  0x00, 0x24, 0x00, 0x54, 0x00, 0x02, 0x00, 0x26,
		  0x00, pipe_low, pipe_high, 0x35, 0x00, 0x00, 0x5c, 0x00,
		  0x50, 0x00, 0x49, 0x00, 0x50, 0x00, 0x45, 0x00,
		  0x5C, 0x00, 0x00, 0x00, 0x00, 0x5c, 0x05, 0x00,
		  0x00, 0x03, 0x10, 0x00, 0x00, 0x00, 0x24, 0x00,
		  0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0C, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x10, 0xFF,
		  0x12, 0x00, 0x30, 0x39, 0x01, 0x00, 0x00, 0x00,
		  0x00, 0x02);
		  

 send(socket:soc, data:req);
 r = smb_recv(socket:soc, length:4096);
 if(strlen(r) < 10)return(FALSE);
 if(ord(r[9])==0)return(r);
 else return(FALSE);
}
#----------------------------------------------------------#
# RegOpenHKCR()                                            #
#----------------------------------------------------------#
function registry_open_hkcr(soc, uid, tid, pipe)
{
 local_var req, tid_low, tid_high, uid_low, uid_high, pipe_low, pipe_high, r;

 tid_low = tid % 256;
 tid_high = tid / 256;
 uid_low = uid % 256;
 uid_high = uid / 256;
 pipe_low = pipe % 256;
 pipe_high = pipe / 256;
 
 req = raw_string(0x00, 0x00,
 		  0x00, 0x78, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
		  0x00, 0x00, 0x00, 0x18, 0x03, 0x80, 0x1D, 0x83,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, tid_low, tid_high, 0x00, 0x28, uid_low, uid_high,
		  g_mlo, g_mhi, 0x10, 0x00, 0x00, 0x24, 0x00, 0x00,
		  0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54,
		  0x00, 0x24, 0x00, 0x54, 0x00, 0x02, 0x00, 0x26,
		  0x00, pipe_low, pipe_high, 0x35, 0x00, 0x00, 0x5c, 0x00,
		  0x50, 0x00, 0x49, 0x00, 0x50, 0x00, 0x45, 0x00,
		  0x5C, 0x00, 0x00, 0x00, 0x00, 0x5c, 0x05, 0x00,
		  0x00, 0x03, 0x10, 0x00, 0x00, 0x00, 0x24, 0x00,
		  0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0C, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0xFF,
		  0x12, 0x00, 0x30, 0x39, 0x01, 0x00, 0x00, 0x00,
		  0x00, 0x02);
		  

 send(socket:soc, data:req);
 r = smb_recv(socket:soc, length:4096);
 if(strlen(r) < 10)return(FALSE);
 if(ord(r[9])==0)return(r);
 else return(FALSE);
}
#----------------------------------------------------------#
# RegFlush()						   #
#----------------------------------------------------------#
function registry_flush(soc, uid, tid, pipe, reply)
{
 local_var magic, req, r, tid_low, tid_high, uid_low, uid_high, pipe_low, pipe_high, name, data, i, len;
 
 tid_low = tid % 256;
 tid_high = tid / 256;
 
 uid_low = uid % 256;
 uid_high = uid / 256;
 
 pipe_low = pipe % 256;
 pipe_high = pipe / 256;
 
 magic = raw_string(ord(reply[84]));		  
 for(i=1;i<20;i=i+1)
 {
  magic = magic + raw_string(ord(reply[84+i]));
 }

 req = raw_string(0x00, 0x00, 0x00, 0x78, 0xFF, 0x53, 
		  0x4D, 0x42, 0x25, 0x00, 0x00, 0x00, 0x00, 0x08,
		  0x01, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, tid_low, tid_high,
		  0x00, 0x28, uid_low, uid_high, g_mlo, g_mhi, 0x10, 0x00,
		  0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x4c, 0x00, 0x2c, 0x00, 0x4c,
		  0x00, 0x02, 0x00, 0x26, 0x00, pipe_low, pipe_high, 0x35,
		  0x00, 0x5c, 0x50, 0x49, 0x50, 0x45, 0x5c, 0x00,
		  0x00, 0x00, 0x05, 0x00, 0x00, 0x03, 0x10, 0x00,
		  0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0xcf, 0x01,
		  0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x0b, 0x00) + magic;
		  
		  
		  
 send(socket:soc, data:req);
 r = smb_recv(socket:soc, length:65535);
 return substr(r, strlen(r) - 4, strlen(r) - 1);
}
  
#----------------------------------------------------------#
# RegClose()                                               #
#----------------------------------------------------------#

function registry_close(soc, uid, tid, pipe, reply)
{
 local_var magic, req, r, tid_low, tid_high, uid_low, uid_high, pipe_low, pipe_high, name, data, i, len;
 
 tid_low = tid % 256;
 tid_high = tid / 256;
 
 uid_low = uid % 256;
 uid_high = uid / 256;
 
 pipe_low = pipe % 256;
 pipe_high = pipe / 256;
 
 magic = raw_string(ord(reply[84]));		  
 for(i=1;i<20;i=i+1)
 {
  magic = magic + raw_string(ord(reply[84+i]));
 }

 req = raw_string(0x00, 0x00, 0x00, 0x78, 0xFF, 0x53, 
		  0x4D, 0x42, 0x25, 0x00, 0x00, 0x00, 0x00, 0x08,
		  0x01, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, tid_low, tid_high,
		  0x00, 0x28, uid_low, uid_high, g_mlo, g_mhi, 0x10, 0x00,
		  0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x4c, 0x00, 0x2c, 0x00, 0x4c,
		  0x00, 0x02, 0x00, 0x26, 0x00, pipe_low, pipe_high, 0x35,
		  0x00, 0x5c, 0x50, 0x49, 0x50, 0x45, 0x5c, 0x00,
		  0x00, 0x00, 0x05, 0x00, 0x00, 0x03, 0x10, 0x00,
		  0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0xcf, 0x01,
		  0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x05, 0x00) + magic;
		  
		  
		  
 send(socket:soc, data:req);
 r = smb_recv(socket:soc, length:65535);
 return substr(r, strlen(r) - 4, strlen(r) - 1);
}

#----------------------------------------------------------#
# RegDelKey()						   #
#----------------------------------------------------------#

function registry_delete_key(soc, uid, tid, pipe, key, reply )
{
 local_var _na_start, i, error;

 key_len = strlen(key) + 1;
 key_len_hi = key_len / 256;
 key_len_lo = key_len % 256;
 
 
 tid_low = tid % 256;
 tid_high = tid / 256;
 uid_low = uid % 256;
 uid_high = uid / 256;
 pipe_low = pipe % 256;
 pipe_high = pipe / 256;
 uc = unicode3(data:key);
 
 len = 148 + strlen(uc);
 
 len_hi = len / 256;
 len_lo = len % 256;
 
 
 z = 40 + strlen(uc);
 z_lo = z % 256;
 z_hi = z / 256;
 
 y = 81 + strlen(uc);
 y_lo = y % 256;
 y_hi = y / 256;
 
 x = 64 + strlen(uc);
 x_lo = x % 256;
 x_hi = x / 256;
 
 if(strlen(reply) < 17)exit(0);
 magic1 = raw_string(ord(reply[16]), ord(reply[17]));
 
 req = raw_string(0x00, 0x00,
 		  len_hi, len_lo, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
		  0x00, 0x00, 0x00, 0x18, 0x03, 0x80)
		  +
		  magic1 +
		 raw_string(
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00,tid_low, tid_high, 0x00, 0x28, uid_low, uid_high,
		  g_mlo, g_mhi, 0x10, 0x00, 0x00, x_lo, x_hi, 0x00,
		  0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54,
		  0x00, x_lo, x_hi, 0x54, 0x00, 0x02, 0x00, 0x26,
		  0x00, pipe_low, pipe_high, y_lo, y_hi, 0x00, 0x5C, 0x00,
		  0x50, 0x00, 0x49, 0x00, 0x50, 0x00, 0x45, 0x00,
		  0x5C, 0x00, 0x00, 0x00, 0x00, 0xb9, 0x05, 0x00,
		  0x00, 0x03, 0x10, 0x00, 0x00, 0x00, x_lo, x_hi,
		  0x00, 0x00, 0x02, 0x00, 0x00, 0x00, z_lo, z_hi,
		  0x00, 0x00, 0x00, 0x00, 0x07, 0x00);
		  
 magic = raw_string(ord(reply[84]));
 for(i=1;i<20;i=i+1)
 {
  magic = magic + raw_string(ord(reply[84+i]));
 }

 x = strlen(key) + strlen(key) + 2;
 x_lo = x % 256;
 x_hi = x / 256;
 
 req = req + magic + raw_string(x_lo, x_hi, x_lo, x_hi, 0x01, 0x00,
 		0x00, 0x00, key_len_lo, key_len_hi, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, key_len_lo, key_len_hi, 0x00) +
		uc + raw_string(0);
		  

 send(socket:soc, data:req);
 r = smb_recv(socket:soc, length:4096);
 if(strlen(r) < 10)return(1);
 error = substr(r, strlen(r) - 4, strlen(r) - 1);
 return ( ( int(ord(error[3])) * 256 + int(ord(error[2])) ) * 256 + int(ord(error[1])) * 256 ) + int(ord(error[0]));
}
#----------------------------------------------------------#
# RegDelValue()						   #
#----------------------------------------------------------#

function registry_delete_value(soc, uid, tid, pipe, value, reply )
{
 local_var _na_start, i, error;

 key_len = strlen(value) + 1;
 key_len_hi = key_len / 256;
 key_len_lo = key_len % 256;
 
 
 tid_low = tid % 256;
 tid_high = tid / 256;
 uid_low = uid % 256;
 uid_high = uid / 256;
 pipe_low = pipe % 256;
 pipe_high = pipe / 256;
 uc = unicode3(data:value);
 
 len = 148 + strlen(uc);
 
 len_hi = len / 256;
 len_lo = len % 256;
 
 
 z = 40 + strlen(uc);
 z_lo = z % 256;
 z_hi = z / 256;
 
 y = 81 + strlen(uc);
 y_lo = y % 256;
 y_hi = y / 256;
 
 x = 64 + strlen(uc);
 x_lo = x % 256;
 x_hi = x / 256;
 
 if(strlen(reply) < 17)exit(0);
 magic1 = raw_string(ord(reply[16]), ord(reply[17]));
 
 req = raw_string(0x00, 0x00,
 		  len_hi, len_lo, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
		  0x00, 0x00, 0x00, 0x18, 0x03, 0x80)
		  +
		  magic1 +
		 raw_string(
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00,tid_low, tid_high, 0x00, 0x28, uid_low, uid_high,
		  g_mlo, g_mhi, 0x10, 0x00, 0x00, x_lo, x_hi, 0x00,
		  0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54,
		  0x00, x_lo, x_hi, 0x54, 0x00, 0x02, 0x00, 0x26,
		  0x00, pipe_low, pipe_high, y_lo, y_hi, 0x00, 0x5C, 0x00,
		  0x50, 0x00, 0x49, 0x00, 0x50, 0x00, 0x45, 0x00,
		  0x5C, 0x00, 0x00, 0x00, 0x00, 0xb9, 0x05, 0x00,
		  0x00, 0x03, 0x10, 0x00, 0x00, 0x00, x_lo, x_hi,
		  0x00, 0x00, 0x97, 0x00, 0x00, 0x00, z_lo, z_hi,
		  0x00, 0x00, 0x00, 0x00, 0x08, 0x00);
		  
 magic = raw_string(ord(reply[84]));
 for(i=1;i<20;i=i+1)
 {
  magic = magic + raw_string(ord(reply[84+i]));
 }

 x = strlen(value) + strlen(value) + 2;
 x_lo = x % 256;
 x_hi = x / 256;
 
 req = req + magic + raw_string(x_lo, x_hi, x_lo, x_hi, 0x01, 0x00,
 		0x00, 0x00, key_len_lo, key_len_hi, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, key_len_lo, key_len_hi, 0x00) +
		uc + raw_string(0);
		  

 send(socket:soc, data:req);
 r = smb_recv(socket:soc, length:4096);
 if(strlen(r) < 10)return(1);
 error = substr(r, strlen(r) - 4, strlen(r) - 1);
 
 return ( ( int(ord(error[3])) * 256 + int(ord(error[2])) ) * 256 + int(ord(error[1])) * 256 ) + int(ord(error[0]));
}
#--------------------------------------------------------------#
# RegShutdown()                                                #
#--------------------------------------------------------------#
function registry_shutdown(soc, uid, tid, pipe, message, timeout, reboot, closeapps )
{
 local_var _na_start, i, error, msg_len, msg_len_hi, msg_len_lo, tid_low, tid_high, uid_low, uid_high, pipe_low, pipe_high, uc;

 msg_len = strlen(message) + 1;
 msg_len_hi = msg_len / 256;
 msg_len_lo = msg_len % 256;
 
 
 tid_low = tid % 256;
 tid_high = tid / 256;
 uid_low = uid % 256;
 uid_high = uid / 256;
 pipe_low = pipe % 256;
 pipe_high = pipe / 256;
 uc = unicode4(data:message);
 
 len = 146 + strlen(uc);
 
 len_hi = len / 256;
 len_lo = len % 256;
 
 
 z = 38 + strlen(uc);
 z_lo = z % 256;
 z_hi = z / 256;
 
 y = 79 + strlen(uc);
 y_lo = y % 256;
 y_hi = y / 256;
 
 x = 62 + strlen(uc);
 x_lo = x % 256;
 x_hi = x / 256;
 
 
 req = raw_string(0x00, 0x00,
 		  len_hi, len_lo, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
		  0x00, 0x00, 0x00, 0x18, 0x03, 0x80, 0x00, 0x00 ) +
		 raw_string(
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00,tid_low, tid_high, 0x00, 0x28, uid_low, uid_high,
		  g_mlo, g_mhi, 0x10, 0x00, 0x00, x_lo, x_hi, 0x00,
		  0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54,
		  0x00, x_lo, x_hi, 0x54, 0x00, 0x02, 0x00, 0x26,
		  0x00, pipe_low, pipe_high, y_lo, y_hi, 0x00, 0x5C, 0x00,
		  0x50, 0x00, 0x49, 0x00, 0x50, 0x00, 0x45, 0x00,
		  0x5C, 0x00, 0x00, 0x00, 0x00, 0xb9, 0x05, 0x00,
		  0x00, 0x03, 0x10, 0x00, 0x00, 0x00, x_lo, x_hi,
		  0x00, 0x00, 0x02, 0x00, 0x00, 0x00, z_lo, z_hi,
		  0x00, 0x00, 0x00, 0x00, 0x18, 0x00);

 x = strlen(message) + strlen(message);
 x_lo = x % 256;
 x_hi = x / 256;
 y = x + 2;
 y_lo = y % 256;
 y_hi = y / 256;

 msg_len2 = msg_len - 1;
 msg_len2_lo = msg_len2 % 256;
 msg_len2_hi = msg_len2 / 256;

 req += raw_string( 0x01, 0x00, 0x00, 0x00,  # ptr_1
		    0x01, 0x00, 0x00, 0x00,  # ptr_2
		    0x01, 0x00, 0x00, 0x00,  # ptr_3
		    x_lo, x_hi,		     # uni_str_len
		    y_lo, y_hi,		     # max_str_len
		    0x01, 0x00, 0x00, 0x00,  # buffer
		    msg_len_lo, msg_len_hi, 0x00, 0x00,  # uni_max_len
		    0x00, 0x00, 0x00, 0x00 , # undoc
		    msg_len2_lo, msg_len2_hi, 0x00, 0x00  # str_max_len
	 );
		    
		  
 req += uc;
 req += raw_string(timeout % 256, (timeout/256) % 256, (timeout/(256*256)) % 256, timeout / (256*256*256));

 
 if ( closeapps ) req += raw_string(0x01);
 else req += raw_string(0x00);
 
 if ( reboot ) req += raw_string(0x01);
 else req += raw_string(0x00);

		  

 send(socket:soc, data:req);
 r = smb_recv(socket:soc, length:4096);
 if(strlen(r) < 10)return(1);
 error = substr(r, strlen(r) - 4, strlen(r) - 1);
 return ( ( int(ord(error[3])) * 256 + int(ord(error[2])) ) * 256 + int(ord(error[1])) * 256 ) + int(ord(error[0]));
}
#----------------------------------------------------------#
# RegEnumKey()                                             #
#----------------------------------------------------------#
function registry_enum_key(soc, uid, tid, pipe, reply)
{

 local_var magic, req, r, tid_low, tid_high, uid_low, uid_high, pipe_low, pipe_high, name, data, list, i, j;
 
 list = make_list();
 tid_low = tid % 256;
 tid_high = tid / 256;
 
 uid_low = uid % 256;
 uid_high = uid / 256;
 
 pipe_low = pipe % 256;
 pipe_high = pipe / 256;
 
 magic = raw_string(ord(reply[84]));		  
 for(i=1;i<20;i=i+1)
 {
  magic = magic + raw_string(ord(reply[84+i]));
 }

 for(j=0;j>=0;j++)
 {
 req = raw_string(0x00, 0x00, 0x00, 0xa8, 0xFF, 0x53, 
		  0x4D, 0x42, 0x25, 0x00, 0x00, 0x00, 0x00, 0x08,
		  0x01, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, tid_low, tid_high,
		  0x00, 0x28, uid_low, uid_high, g_mlo, g_mhi, 0x10, 0x00,
		  0x00, 0x5c, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x4c, 0x00, 0x5c, 0x00, 0x4c,
		  0x00, 0x02, 0x00, 0x26, 0x00, pipe_low, pipe_high, 0x65,
		  0x00, 0x5c, 0x50, 0x49, 0x50, 0x45, 0x5c, 0x00,
		  0x00, 0x00, 0x05, 0x00, 0x00, 0x03, 0x10, 0x00,
		  0x00, 0x00, 0x5c, 0x00, 0x00, 0x00, 0xff, 0x00,
		  0x00, 0x00, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x09, 0x00); 
		  
		  
		  
  req2= magic + raw_string(
                  j % 256, j / 256, 0x00, 0x00,  # key ID
		  0x00, 0x00, 		    # key name len
		  0x14, 0x04,  		    # unknown
                  0x01, 0x00, 0x00, 0x00,   # ptr
		  0x0a, 0x02, 0x00, 0x00,   # unknown_2
                  0x00, 0x00, 0x00, 0x00,   # padding
		  0x00, 0x00, 0x00, 0x00,   # padding
                  0x01, 0x00, 0x00, 0x00,   # ptr2
                  0x00, 0x00, 0x00, 0x00,   # padding2
                  0x00, 0x00, 0x00, 0x00,   # padding2
		  0x01, 0x00, 0x00, 0x00,   # ptr3 
		  0xff, 0xff, 0xff, 0xff,   # smb_io_time low
	          0xff, 0xff, 0xff, 0x7f   # smb_io_time high
		  );

	
 req += req2;
 send(socket:soc, data:req);
 r = smb_recv(socket:soc, length:65535);
 if(strlen(r) < 80)return(NULL);

 len = ord(r[60+24+16]);
 if (!len)
   break;

 name = "";
 for (i=0;i<len - 1; i++)
    name += r[60+43+i*2+1];

 list = make_list(list, name);
 }

 return list;
}


#----------------------------------------------------------#
# RegEnumValue()                                           #
#----------------------------------------------------------#
# Author: Nicolas Pouvesle
function registry_enum_value(soc, uid, tid, pipe, reply)
{
 local_var magic, req, r, tid_low, tid_high, uid_low, uid_high, pipe_low, pipe_high, name, data, list, i, j;
 
 tid_low = tid % 256;
 tid_high = tid / 256;
 
 uid_low = uid % 256;
 uid_high = uid / 256;
 
 pipe_low = pipe % 256;
 pipe_high = pipe / 256;
 
 magic = raw_string(ord(reply[84]));		  
 for(i=1;i<20;i=i+1)
 {
  magic = magic + raw_string(ord(reply[84+i]));
 }

 for(j=0;j>=0;j++)
 {
 req = raw_string(0x00, 0x00,
 		  0x00, 0xC0, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
		  0x00, 0x00, 0x00, 0x18, 0x03, 0x80, 0x00, 0x83,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, tid_low, tid_high, 0x00, 0x28, uid_low, uid_high,
		  g_mlo, g_mhi, 0x10, 0x00, 0x00, 0x6C, 0x00, 0x00,
		  0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54,
		  0x00, 0x6C, 0x00, 0x54, 0x00, 0x02, 0x00, 0x26,
		  0x00, pipe_low, pipe_high, 0x59, 0x00, 0x00, 0x5C, 0x00,
		  0x50, 0x00, 0x49, 0x00, 0x50, 0x00, 0x45, 0x00,
		  0x5C, 0x00, 0x00, 0x00, 0xEE, 0xD5, 0x05, 0x00,
		  0x00, 0x03, 0x10, 0x00, 0x00, 0x00, 0x6C, 0x00,
		  0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x30, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x0A, 0x00);
		  
  req = req + magic + raw_string(
                  j % 256, j / 256, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
                  0xcc, 0xf9, 0x06, 0x00, 0x00, 0x01, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0xa0, 0xf9, 0x06, 0x00, 0x59, 0xe6, 0x07, 0x00,
                  0x00, 0xc4, 0x04, 0x01, 0x00, 0x80, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0xb0, 0xf9, 0x06, 0x00, 0x00, 0x80, 0x00, 0x00,
                  0x94, 0xf9, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00); 

	
 send(socket:soc, data:req);
 r = smb_recv(socket:soc, length:65535);
 if(strlen(r) < 80)return(NULL);

 len = ord(r[60+24]);
 if (!len)
   break;

 name = "";
 for (i=0;i<len;i = i+2)
    name += r[60+43+i+1];

 if (!ord(r[60+43+len+2])) len+=2;

 dlen = ord(r[60+43+len+21]);

 data = "";
 for (i=0;i<dlen;i = i+2)
    data += r[60+43+len+24+i+1];

 list[j*2] = name;
 list[j*2+1] = data;
 }

 return list;
}
#---------------------------------------------------------------------#
# RegOpenKey()							      #
#---------------------------------------------------------------------#
		 
function registry_get_key(soc, uid, tid, pipe, key, reply, write)
{
 local_var _na_start, i, error, access_mask;

 key_len = strlen(key) + 1;
 key_len_hi = key_len / 256;
 key_len_lo = key_len % 256;
 
 
 
 tid_low = tid % 256;
 tid_high = tid / 256;
 uid_low = uid % 256;
 uid_high = uid / 256;
 pipe_low = pipe % 256;
 pipe_high = pipe / 256;
 uc = unicode(data:key);

 if ( write ) access_mask = raw_string(0x19, 0x00, 0x02, 0x02);
 else access_mask = raw_string(0x19, 0x00, 0x02, 0x00);
 
 uc += access_mask;
 len = 148 + strlen(uc);
 
 len_hi = len / 256;
 len_lo = len % 256;
 
 
 z = 40 + strlen(uc);
 z_lo = z % 256;
 z_hi = z / 256;
 
 y = 81 + strlen(uc);
 y_lo = y % 256;
 y_hi = y / 256;
 
 x = 64 + strlen(uc);
 x_lo = x % 256;
 x_hi = x / 256;
 
 if(strlen(reply) < 17)exit(0);
 magic1 = raw_string(ord(reply[16]), ord(reply[17]));
 
 req = raw_string(0x00, 0x00,
 		  len_hi, len_lo, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
		  0x00, 0x00, 0x00, 0x18, 0x03, 0x80)
		  +
		  magic1 +
		 raw_string(
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00,tid_low, tid_high, 0x00, 0x28, uid_low, uid_high,
		  g_mlo, g_mhi, 0x10, 0x00, 0x00, x_lo, x_hi, 0x00,
		  0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54,
		  0x00, x_lo, x_hi, 0x54, 0x00, 0x02, 0x00, 0x26,
		  0x00, pipe_low, pipe_high, y_lo, y_hi, 0x00, 0x5C, 0x00,
		  0x50, 0x00, 0x49, 0x00, 0x50, 0x00, 0x45, 0x00,
		  0x5C, 0x00, 0x00, 0x00, 0x00, 0xb9, 0x05, 0x00,
		  0x00, 0x03, 0x10, 0x00, 0x00, 0x00, x_lo, x_hi,
		  0x00, 0x00, 0x02, 0x00, 0x00, 0x00, z_lo, z_hi,
		  0x00, 0x00, 0x00, 0x00, 0x0F, 0x00);
		  
 magic = raw_string(ord(reply[84]));
 for(i=1;i<20;i=i+1)
 {
  magic = magic + raw_string(ord(reply[84+i]));
 }

 x = strlen(key) + strlen(key) + 2;
 x_lo = x % 256;
 x_hi = x / 256;
 
 req = req + magic + raw_string(x_lo, x_hi, 0x0A, 0x02, 0x00, 0xEC,
 		0xFD, 0x7F, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, key_len_lo, key_len_hi, 0x00, 0x00) +
		uc;
		  

 send(socket:soc, data:req);
 r = smb_recv(socket:soc, length:4096);
 if(strlen(r) < 10)return(FALSE);
 
 len = ord(r[2])*256;
 len = len + ord(r[3]);
 if(len < 100)return(FALSE);

  # pull the last 4 bytes off the end
 _na_start = (strlen(r) - 4);
 for (_na_cnt = 0; _na_cnt < 4; _na_cnt++)
     _na_data = _na_data + r[_na_start + _na_cnt];

 # access denied, returned by Windows XP+
 if (_na_data == raw_string(0x05,0x00,0x00,0x00) || _na_data == raw_string(0x02, 0x00, 0x00, 0x00))
    return(FALSE);

 if(ord(r[9])==0)return(r);
 else return(FALSE);
}



#------------------------------------------------------------------#
# Return TRUE if someone else than the admin group, the owner      #
# and the local system can modify the key                          #
#------------------------------------------------------------------#

function registry_key_writeable_by_non_admin(security_descriptor)
{
 local_var r, num_aces, size, start, s, i, mask, z, id_auth, num_auth, sub_auth, k, n, sid;
 local_var WRITE, ADMIN_SID, LOCAL_SYSTEM_SID, CREATOR_OWNER_SID; 
 
 
  if(isnull(security_descriptor))
  	return(NULL);
	
  # write mask
 WRITE = 0x00010000 | 0x00040000 | 0x00080000 | 0x00000002 | 0x000004;

 # sids - written the nessus way

 ADMIN_SID = "1-000005-32-544";
 LOCAL_SYSTEM_SID = "1-000005-18";
 CREATOR_OWNER_SID = "1-000003-0";


 r = security_descriptor;
 num_aces = 0;
 num_aces = ord(r[135]);
 num_aces = ord(r[134])+ num_aces*256;
 num_aces = ord(r[133])+ num_aces*256;
 num_aces = ord(r[132])+ num_aces*256;
 start = 137;
 
 size = 0;
 s = start;

 for(i=0;i<num_aces;i=i+1)
 {
  z = ord(r[s+2]);
  z = ord(r[s+1])+z*256;
  mask = ord(r[s+6]);
  mask = ord(r[s+5])+mask*256;
  mask = ord(r[s+4])+mask*256;
  mask = ord(r[s+3])+mask*256;
  
  id_auth = ord(r[s+14]);
  id_auth = string(ord(r[s+13]), id_auth);
  id_auth = string(ord(r[s+12]), id_auth);
  id_auth = string(ord(r[s+11]), id_auth);
  id_auth = string(ord(r[s+10]), id_auth);
  id_auth = string(ord(r[s+9]), id_auth);
  
  num_auths = ord(r[s+8]);
  sub_auths = "";
  k = 15;
  for(c = 0;c < num_auths; c = c+1)
  {
  n = ord(r[s+k+3]);
  n = ord(r[s+k+2])+n*256;
  n = ord(r[s+k+1])+n*256;
  n = ord(r[s+k])+n*256;
  k = k + 4;
  sub_auths = string(sub_auths,"-",n);
  }
  
  sid = string(ord(r[s+7]), "-", id_auth, sub_auths);
  # display("sid = ", sid, "\n");
  if(mask & WRITE){
    #     display("writeable by ", sid, "\n");
    #	  display(mask & WRITE, "\n");
	
	 if((sid != ADMIN_SID) &&  
	    (sid != LOCAL_SYSTEM_SID) && 
	    (sid != CREATOR_OWNER_SID))
	 {
	   #display("sid != ", CREATOR_OWNER_SID, "\n");
	   #display(mask, "\n");
	   return(TRUE);
	 }
      }
  s = s + z;
 } 
 return(FALSE);
}


#---------------------------------------------------------------------#
# Get the security descriptor for a key                               #
#---------------------------------------------------------------------#



function registry_get_key_security(soc, uid, tid, pipe, reply)
{
 local_var magic, req, r, tid_low, tid_high, uid_low, uid_high, pipe_low, pipe_high;
 
 tid_low = tid % 256;
 tid_high = tid / 256;
 
 uid_low = uid % 256;
 uid_high = uid / 256;
 
 pipe_low = pipe % 256;
 pipe_high = pipe / 256;
 
 req = raw_string(0x00, 0x00,
 		  0x00, 0x90, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
		  0x00, 0x00, 0x00, 0x18, 0x03, 0x80, 0x00, 0x83,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, tid_low, tid_high, 0x00, 0x28, uid_low, uid_high,
		  g_mlo, g_mhi, 0x10, 0x00, 0x00, 0x3C, 0x00, 0x00,
		  0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54,
		  0x00, 0x3C, 0x00, 0x54, 0x00, 0x02, 0x00, 0x26,
		  0x00, pipe_low, pipe_high, 0x4D, 0x00, 0x00, 0x5C, 0x00,
		  0x50, 0x00, 0x49, 0x00, 0x50, 0x00, 0x45, 0x00,
		  0x5C, 0x00, 0x00, 0x00, 0xEE, 0xD5, 0x05, 0x00,
		  0x00, 0x03, 0x10, 0x00, 0x00, 0x00, 0x3C, 0x00,
		  0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x24, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x0c, 0x00);
 if(strlen(reply) < 104)return(FALSE);
 
 magic = raw_string(ord(reply[84]));		  
 for(i=1;i<20;i=i+1)
 {
  magic = magic + raw_string(ord(reply[84+i]));
 }
 
 req = req + magic + raw_string(0x04) + crap(data:raw_string(0), length:15);
 
 send(socket:soc, data:req);
 r = smb_recv(socket:soc, length:65535);
 
 
 len1 =  ord(r[strlen(r) - 12]);
 len2 = ord(r[strlen(r) - 11]);
 len3 = ord(r[strlen(r) - 10]);
 len4 = ord(r[strlen(r) - 9]);
 req = raw_string(0x00, 0x00,
 		  0x00, 0x9C, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
		  0x00, 0x00, 0x00, 0x18, 0x03, 0x80, 0x00, 0x83,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, tid_low, tid_high, 0x00, 0x28, uid_low, uid_high,
		  g_mlo, g_mhi, 0x10, 0x00, 0x00, 0x48, 0x00, 0x00,
		  0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54,
		  0x00, 0x48, 0x00, 0x54, 0x00, 0x02, 0x00, 0x26,
		  0x00, pipe_low, pipe_high, 0x59, 0x00, 0x00, 0x5C, 0x00,
		  0x50, 0x00, 0x49, 0x00, 0x50, 0x00, 0x45, 0x00,
		  0x5C, 0x00, 0x00, 0x00, 0xEE, 0xD5, 0x05, 0x00,
		  0x00, 0x03, 0x10, 0x00, 0x00, 0x00, 0x48, 0x00,
		  0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x30, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x0c, 0x00);
		  
  req = req + magic + raw_string(0x04, 0x00, 0x00, 0x00, 0x38, 0x8d,
       0x07, 0x00, len1, len2, len3, len4, 0x00, 0x00,
       0x00, 0x00, len1, len2, len3, len4, 0x00, 0x00,
       0x00, 0x00, 0x00, 0x00, 0x00, 0x00);		  
	
	
 send(socket:soc, data:req);
 r = smb_recv(socket:soc, length:65535);
 if(strlen(r) < 150)return(NULL);
 return(r);
}

 
#---------------------------------------------------------------------#
# returns 'TRUE' if <key> exists				      #
#---------------------------------------------------------------------#
function registry_key_exists(key)
{
 local_var name, domain, _smb_port, login, pass, soc, r, uid, tid, pipe, ret, prot;
 local_var magic, flag, i;
 
name =  kb_smb_name();
if(!name)exit(0);


domain = kb_smb_domain();
_smb_port = kb_smb_transport();
if(!_smb_port)exit(0);


if(!get_port_state(_smb_port))return(FALSE);

login = kb_smb_login();
pass  = kb_smb_password();

if(!login)login = "";
if(!pass) pass = "";

	  
soc = open_sock_tcp(_smb_port);
if ( ! soc ) return NULL;

#
# Request the session
# 
r = smb_session_request(soc:soc,  remote:name);
if(!r)return(FALSE);

#
# Negociate the protocol
#
prot = smb_neg_prot(soc:soc);
if(!prot)return(FALSE);


#
# Set up our session
#
r = smb_session_setup(soc:soc, login:login, password:pass, domain:domain, prot:prot);
if(!r)return(FALSE);
# and extract our uid
uid = session_extract_uid(reply:r);


#
# Connect to the remote IPC and extract the TID
# we are attributed
#      
r = smb_tconx(soc:soc, name:name, uid:uid, share:"IPC$");
# and extract our tree id
tid = tconx_extract_tid(reply:r);
if(!tid)return(NULL);

#
# Create a pipe to \winreg
#
r = smbntcreatex(soc:soc, uid:uid, tid:tid, name:"\winreg");
if(!r)return(NULL);
# and extract its ID
pipe = smbntcreatex_extract_pipe(reply:r);

#
# Setup things
#



r = pipe_accessible_registry(soc:soc, uid:uid, tid:tid, pipe:pipe);
if(!r)return(FALSE);
r = registry_open_hklm(soc:soc, uid:uid, tid:tid, pipe:pipe);
r2 = registry_get_key(soc:soc, uid:uid, tid:tid, pipe:pipe, key:key, reply:r);
close(soc);
registry_close(soc:soc, uid:uid, tid:tid, pipe:pipe, reply:r2);
registry_close(soc:soc, uid:uid, tid:tid, pipe:pipe, reply:r);
if ( ! r2 && strlen(r2) < 104) return NULL;
flag = 0;
for(i=1;i<20;i=i+1)
 {
  if ( ord(r2[84+i]) != 0 ) flag = 1;
 }

if ( flag ) return TRUE;
else return NULL;

}
		 
#---------------------------------------------------------------------#
# returns 'TRUE' if <key> is writeable				      #
#---------------------------------------------------------------------#


function registry_get_acl(key)
{
 local_var name, domain, _smb_port, login, pass, soc, r, uid, tid, pipe, ret, prot;
 
name =  kb_smb_name();
if(!name)exit(0);


domain = kb_smb_domain();
_smb_port = kb_smb_transport();
if(!_smb_port)exit(0);


if(!get_port_state(_smb_port))return(FALSE);

login = kb_smb_login();
pass  = kb_smb_password();

if(!login)login = "";
if(!pass) pass = "";

	  
soc = open_sock_tcp(_smb_port);
if ( ! soc ) return NULL;

#
# Request the session
# 
r = smb_session_request(soc:soc,  remote:name);
if(!r)return(FALSE);

#
# Negociate the protocol
#
prot = smb_neg_prot(soc:soc);
if(!prot)return(FALSE);


#
# Set up our session
#
r = smb_session_setup(soc:soc, login:login, password:pass, domain:domain, prot:prot);
if(!r)return(FALSE);
# and extract our uid
uid = session_extract_uid(reply:r);


#
# Connect to the remote IPC and extract the TID
# we are attributed
#      
r = smb_tconx(soc:soc, name:name, uid:uid, share:"IPC$");
# and extract our tree id
tid = tconx_extract_tid(reply:r);
if(!tid)return(NULL);

#
# Create a pipe to \winreg
#
r = smbntcreatex(soc:soc, uid:uid, tid:tid, name:"\winreg");
if(!r)return(NULL);
# and extract its ID
pipe = smbntcreatex_extract_pipe(reply:r);

#
# Setup things
#



r = pipe_accessible_registry(soc:soc, uid:uid, tid:tid, pipe:pipe);
if(!r)return(FALSE);
r = registry_open_hklm(soc:soc, uid:uid, tid:tid, pipe:pipe);
if(strlen(key))
 r2 = registry_get_key(soc:soc, uid:uid, tid:tid, pipe:pipe, key:key, reply:r);
else 
 r2 = r;


if(r2)
 {
 r3 =  registry_get_key_security(soc:soc, uid:uid, tid:tid, pipe:pipe, reply:r2);
 registry_close(soc:soc, uid:uid, tid:tid, pipe:pipe, reply:r2);
 if ( strlen(key) )  registry_close(soc:soc, uid:uid, tid:tid, pipe:pipe, reply:r);
 close(soc);
 
 if(strlen(r3) < 100)return(NULL);
 return(r3);
 }
return(NULL);
}

#---------------------------------------------------------------------#
# Get an item of type reg_sz from the key                             #
#---------------------------------------------------------------------#

function unicode2(data)
{
 len = strlen(data);
 ret = raw_string(0, ord(data[0]));
 
 for(i=1;i<len;i=i+1)
 {
  ret = ret + raw_string(0, ord(data[i]));
 }
 if(len & 1)ret = ret + raw_string(0x00, 0x00); 
 else ret = ret + raw_string(0x00, 0x00, 0x00, 0x63);
 return(ret);
}

function unicode3(data)
{
 len = strlen(data);
 ret = raw_string(0, ord(data[0]));
 
 for(i=1;i<len;i=i+1)
 {
  ret = ret + raw_string(0, ord(data[i]));
 }
 if(len & 1)ret = ret + raw_string(0x00, 0x00); 
 else ret = ret + raw_string(0x00, 0x00, 0x00, 0x00);
 return(ret);
}
function unicode4(data)
{
 len = strlen(data);
 ret = raw_string(0, ord(data[0]));
 
 for(i=1;i<len;i=i+1)
 {
  ret = ret + raw_string(ord(data[i]),0);
 }
 if(len & 1)ret = ret + raw_string(0x00); 
 return(ret);
}

function registry_get_item_sz(soc, uid, tid, pipe, item, reply)
{
 local_var i;
 item_len = strlen(item) + 1;
 item_len_lo = item_len % 256;
 item_len_hi = item_len / 256;
 
 uc2 = unicode2(data:item);
 len = 188 + strlen(uc2);
 len_lo = len % 256;
 len_hi = len / 256;
 
 tid_low = tid % 256;
 tid_high = tid / 256;
 uid_low = uid % 256;
 uid_high = uid / 256;
 pipe_low = pipe % 256;
 pipe_high = pipe / 256;
 
 bcc = 121 + strlen(uc2);
 bcc_lo = bcc % 256;
 bcc_hi = bcc / 256;
 
 y = 80 + strlen(uc2);
 y_lo = y % 256;
 y_hi = y / 256;
 
 z = 104 + strlen(uc2);
 z_lo = z % 256;
 z_hi = z / 256;
 req = raw_string(0x00, 0x00,
 		  len_hi, len_lo, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
		  0x00, 0x00, 0x00, 0x18, 0x03, 0x80, 0x1D, 0x83,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, tid_low, tid_high, 0x00, 0x28, uid_low, uid_high,
		  g_mlo, g_mhi, 0x10, 0x00, 0x00, z_lo, z_hi, 0x00,
		  0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54,
		  0x00, z_lo, z_hi, 0x54, 0x00, 0x02, 0x00, 0x26,
		  0x00, pipe_low, pipe_high, bcc_lo, bcc_hi, 0x00, 0x5C, 0x00,
		  0x50, 0x00, 0x49, 0x00, 0x50, 0x00, 0x45, 0x00,
		  0x5C, 0x00, 0x00, 0x00, 0x00, 0x5C, 0x05, 0x00,
		  0x00, 0x03, 0x10, 0x00, 0x00, 0x00, z_lo, z_hi,
		  0x00, 0x00, 0x03, 0x00, 0x00, 0x00, y_lo, y_hi,
		  0x00, 0x00, 0x00, 0x00, 0x11, 0x00);
		  
 if(strlen(reply) < 104)return(FALSE);
 magic = raw_string(ord(reply[84]));
 for(i=1;i<20;i=i+1)
 {
  magic = magic + raw_string(ord(reply[84+i]));
 }

 x = 2 + strlen(item) + strlen(item);
 x_lo = x % 256;
 x_hi = x / 256;
  
 y = y + 3;
 y_lo = y % 256;
 y_hi = y / 256;
 
  req = req + magic + raw_string(x_lo, x_hi, 0x0A, 0x02, 0x00, 0xEC,
  		0xFD, 0x7F, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, item_len_lo, item_len_hi, 0x00)
		
		+ uc2	+ 
		raw_string(0x00, 0x34, 0xFF,
		0x12, 0x00, 0xEF, 0x10, 0x40, 0x00, 0x18, 0x1E,
		0x7c, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3C, 0xFF,
		0x12, 0x00, 0x00, 0x04, 0x00, 0x00, 0x30, 0xFF,
		0x12, 0x00, 0x00, 0x00, 0x00, 0x00);
		
 send(socket:soc, data:req);
 req = smb_recv(socket:soc, length:4000);		
 return(req);
}		  

#------------------------------------------------------#
# Decode the reply from the registry                   #
#------------------------------------------------------#

function registry_decode_binary(data)
{
 local_var i, o, len, index;

 len = ord(data[2])*256;
 len = len + ord(data[3]);
 if(len < 130)return(NULL);
 
 data_offset = ord(data[52])*256;
 data_offset = data_offset + ord(data[51]) + 4;
 data_len = ord(data[data_offset+43]);
 data_len = data_len * 256;
 data_len = data_len + ord(data[data_offset+44]);
 index = data_offset + 48;
 o = "";
 data_len = data_len - 2;
 for(i=0;i<data_len;i=i+1)
 {
   o = string(o, raw_string(ord(data[index+i])));
 }
 return(o);
}



function registry_decode_sz(data)
{
 local_var i, o, len, index;

 len = ord(data[2])*256;
 len = len + ord(data[3]);
 if(len < 128)return(NULL);
 
 data_offset = ord(data[52])*256;
 data_offset = data_offset + ord(data[51]) + 4;
 data_len = ord(data[data_offset+47]);
 data_len = data_len * 256 + ord(data[data_offset+46]);
 data_len = data_len * 256 + ord(data[data_offset+45]);
 data_len = data_len * 256 + ord(data[data_offset+44]);
 index = data_offset + 48;
 o = "";
 data_len = data_len - 2;
 
 for(i=0;i<data_len;i=i+2)
 {
   o = string(o, raw_string(ord(data[index+i])));
 }
 return(o);
}

#---------------------------------------------------------------------#
#---------------------------------------------------------------------#
# Get an item of type reg_dword from the key                          #
#---------------------------------------------------------------------#

function registry_get_item_dword(soc, uid, tid, pipe, item, reply)
{
 local_var item_len, item_len_lo, item_len_hi, uc2, len, len_lo, len_hi, tid_low, tid_high, uid_low, uid_high;
 local_var pipe_low, pipe_high, bcc, bcc_lo, bcc_hi, y, y_lo, y_hi, z, z_lo, z_hi, req;
 local_var magic, x, x_lo, x_hi;
 item_len = strlen(item) + 1;
 item_len_lo = item_len % 256;
 item_len_hi = item_len / 256;
 
 uc2 = unicode2(data:item);
 len = 188 + strlen(uc2);
 len_lo = len % 256;
 len_hi = len / 256;
 
 tid_low = tid % 256;
 tid_high = tid / 256;
 uid_low = uid % 256;
 uid_high = uid / 256;
 pipe_low = pipe % 256;
 pipe_high = pipe / 256;
 
 bcc = 121 + strlen(uc2);
 bcc_lo = bcc % 256;
 bcc_hi = bcc / 256;
 
 y = 80 + strlen(uc2);
 y_lo = y % 256;
 y_hi = y / 256;
 
 z = 104 + strlen(uc2);
 z_lo = z % 256;
 z_hi = z / 256;
 req = raw_string(0x00, 0x00,
 		  len_hi, len_lo, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
		  0x00, 0x00, 0x00, 0x18, 0x03, 0x80, 0x1D, 0x83,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, tid_low, tid_high, 0x00, 0x28, uid_low, uid_high,
		  g_mlo, g_mhi, 0x10, 0x00, 0x00, z_lo, z_hi, 0x00,
		  0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54,
		  0x00, z_lo, z_hi, 0x54, 0x00, 0x02, 0x00, 0x26,
		  0x00, pipe_low, pipe_high, bcc_lo, bcc_hi, 0x00, 0x5C, 0x00,
		  0x50, 0x00, 0x49, 0x00, 0x50, 0x00, 0x45, 0x00,
		  0x5C, 0x00, 0x00, 0x00, 0x00, 0x5C, 0x05, 0x00,
		  0x00, 0x03, 0x10, 0x00, 0x00, 0x00, z_lo, z_hi,
		  0x00, 0x00, 0x03, 0x00, 0x00, 0x00, y_lo, y_hi,
		  0x00, 0x00, 0x00, 0x00, 0x11, 0x00);
		  
 magic = raw_string(ord(reply[84]));
 for(i=1;i<20;i=i+1)
 {
   magic = magic + raw_string(ord(reply[84+i]));
 }


 x = 2 + strlen(item) + strlen(item);
 x_lo = x % 256;
 x_hi = x / 256;
  
 y = y + 3;
 y_lo = y % 256;
 y_hi = y / 256;
 
  req = req + magic + raw_string(x_lo, x_hi, 0x0A, 0x02, 0x00, 0xEC,
  		0xFD, 0x7F, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, item_len_lo, item_len_hi, 0x00)
		
		+ uc2	+ 
		raw_string(0x00, 0x34, 0xFF,
		0x12, 0x00, 0xEF, 0x10, 0x40, 0x00, 0x18, 0x1E,
		0x7c, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3C, 0xFF,
		0x12, 0x00, 0x00, 0x04, 0x00, 0x00, 0x30, 0xFF,
		0x12, 0x00, 0x00, 0x00, 0x00, 0x00);
		
 send(socket:soc, data:req);
 req = smb_recv(socket:soc, length:4000);		
 return(req);
}		  

#------------------------------------------------------#
# Decode the reply from the registry                   #
#------------------------------------------------------#

function registry_decode_dword(data)
{
 len = ord(data[2])*256;
 len = len + ord(data[3]);
 if(len < 126)return(NULL);
 
 data_offset = ord(data[52])*256;
 data_offset = data_offset + ord(data[51]) + 4;
 data_len = ord(data[data_offset+43]);
 data_len = data_len * 256;
 data_len = data_len + ord(data[data_offset+44]);
 index = data_offset + 48;
 o = "";
 for(i=data_len;i>0;i=i-1)
 {
   t *= 256;
   t += ord(data[index+i-1]);
 }

 return(t);
}
			  
		 
#---------------------------------------------------------------------#
# registry_get_dword()						      #
#---------------------------------------------------------------------#


function registry_get_dword(key, item)
{
 local_var name, port, login, pass, soc, dom, r, prot, value;
 
 if ( get_kb_item("SMB/samba") ) exit(0);
 
 port = kb_smb_transport();
 if(!port)exit(0);

 name = kb_smb_name();
 if(!name)exit(0);


 if(!get_port_state(port))return(FALSE);

 login = kb_smb_login();
 pass  = kb_smb_password();

if(!login)login = "";
if(!pass) pass = "";

 dom = kb_smb_domain();
	  
 soc = open_sock_tcp(port);
 if(!soc)exit(0);

 #
 # Request the session
 # 
 r = smb_session_request(soc:soc,  remote:name);
 if(!r){ close(soc); return NULL;}

 #
 # Negociate the protocol
 #
 prot = smb_neg_prot(soc:soc);
 if(!prot) { close(soc); return NULL;}


 #
 # Set up our session
 #
 r = smb_session_setup(soc:soc, login:login, password:pass, domain:dom, prot:prot);
 if(!r){ close(soc); return NULL;}
 # and extract our uid
 uid = session_extract_uid(reply:r);

 #
 # Connect to the remote IPC and extract the TID
 # we are attributed
 #      
 r = smb_tconx(soc:soc, name:name, uid:uid, share:"IPC$");
 # and extract our tree id
 tid = tconx_extract_tid(reply:r);


 #
 # Create a pipe to \winreg
 #
 r = smbntcreatex(soc:soc, uid:uid, tid:tid, name:"\winreg");
 if(!r){ close(soc); return(NULL); }
 # and extract its ID
 pipe = smbntcreatex_extract_pipe(reply:r);

 #
 # Setup things
 #
 r = pipe_accessible_registry(soc:soc, uid:uid, tid:tid, pipe:pipe);
 if(!r){ close(soc); return(NULL); }
 r = registry_open_hklm(soc:soc, uid:uid, tid:tid, pipe:pipe);

 r2 = registry_get_key(soc:soc, uid:uid, tid:tid, pipe:pipe, key:key, reply:r);
 if(r2)
 {
 r3 =  registry_get_item_dword(soc:soc, uid:uid, tid:tid, pipe:pipe, item:item, reply:r2);
 registry_close(soc:soc, uid:uid, tid:tid, pipe:pipe, reply:r2);
 registry_close(soc:soc, uid:uid, tid:tid, pipe:pipe, reply:r);
 value = registry_decode_dword(data:r3);
 close(soc);
 return(value); 
 }
 close(soc);
 return NULL;
}
			  
#---------------------------------------------------------------------#
# registry_get_binary()						      #
#---------------------------------------------------------------------#
function registry_get_binary(key, item)
{
 local_var name, _smb_port, login, pass, domain, soc, uid, tid, r, prot, pipe;

if ( get_kb_item("SMB/samba") ) exit(0);

name = kb_smb_name();
if(!name)exit(0);

_smb_port = kb_smb_transport();
if(!_smb_port)exit(0);

if(!get_port_state(_smb_port))return(FALSE);

login = kb_smb_login();
pass  = kb_smb_password();

domain = kb_smb_domain();

if(!login)login = "";
if(!pass) pass = "";

	  
soc = open_sock_tcp(_smb_port);
if(!soc)return(FALSE);

#
# Request the session
# 
r = smb_session_request(soc:soc,  remote:name);
if(!r) { close(soc); return(FALSE); }

#
# Negociate the protocol
#
prot = smb_neg_prot(soc:soc);
if(!prot){ close(soc); return(FALSE); }


#
# Set up our session
#
r = smb_session_setup(soc:soc, login:login, password:pass, domain:domain, prot:prot);
if(!r){ close(soc); return(FALSE); }
# and extract our uid
uid = session_extract_uid(reply:r);

#
# Connect to the remote IPC and extract the TID
# we are attributed
#      
r = smb_tconx(soc:soc, name:name, uid:uid, share:"IPC$");
# and extract our tree id
tid = tconx_extract_tid(reply:r);
if(!tid){ close(soc); return(FALSE); }

#
# Create a pipe to \winreg
#
r = smbntcreatex(soc:soc, uid:uid, tid:tid, name:"\winreg");
if(!r){ close(soc); return(FALSE);}
# and extract its ID
pipe = smbntcreatex_extract_pipe(reply:r);

#
# Setup things
#
r = pipe_accessible_registry(soc:soc, uid:uid, tid:tid, pipe:pipe);
if(!r){ close(soc); return(FALSE); }
r = registry_open_hklm(soc:soc, uid:uid, tid:tid, pipe:pipe);

r2 = registry_get_key(soc:soc, uid:uid, tid:tid, pipe:pipe, key:key, reply:r);
if(r2)
{
 r3 =  registry_get_item_sz(soc:soc, uid:uid, tid:tid, pipe:pipe, item:item, reply:r2);
 registry_close(soc:soc, uid:uid, tid:tid, pipe:pipe, reply:r2);
 registry_close(soc:soc, uid:uid, tid:tid, pipe:pipe, reply:r);
 value = registry_decode_binary(data:r3);
 close(soc);
 return(value);
}
close(soc);
return(FALSE);
}
		 
#---------------------------------------------------------------------#
# registry_get_sz()						      #
#---------------------------------------------------------------------#


function registry_get_sz(key, item)
{
 local_var name, _smb_port, login, pass, domain, soc, uid, tid, r, prot, pipe;

if ( get_kb_item("SMB/samba") ) exit(0);

name = kb_smb_name();
if(!name)exit(0);

_smb_port = kb_smb_transport();
if(!_smb_port)exit(0);

if(!get_port_state(_smb_port))return(FALSE);

login = kb_smb_login();
pass  = kb_smb_password();

domain = kb_smb_domain();

if(!login)login = "";
if(!pass) pass = "";

	  
soc = open_sock_tcp(_smb_port);
if(!soc)return(FALSE);

#
# Request the session
# 
r = smb_session_request(soc:soc,  remote:name);
if(!r) { close(soc); return(FALSE); }

#
# Negociate the protocol
#
prot = smb_neg_prot(soc:soc);
if(!prot){ close(soc); return(FALSE); }


#
# Set up our session
#
r = smb_session_setup(soc:soc, login:login, password:pass, domain:domain, prot:prot);
if(!r){ close(soc); return(FALSE); }
# and extract our uid
uid = session_extract_uid(reply:r);

#
# Connect to the remote IPC and extract the TID
# we are attributed
#      
r = smb_tconx(soc:soc, name:name, uid:uid, share:"IPC$");
# and extract our tree id
tid = tconx_extract_tid(reply:r);
if(!tid){ close(soc); return(FALSE); }

#
# Create a pipe to \winreg
#
r = smbntcreatex(soc:soc, uid:uid, tid:tid, name:"\winreg");
if(!r){ close(soc); return(FALSE);}
# and extract its ID
pipe = smbntcreatex_extract_pipe(reply:r);

#
# Setup things
#
r = pipe_accessible_registry(soc:soc, uid:uid, tid:tid, pipe:pipe);
if(!r){ close(soc); return(FALSE); }
r = registry_open_hklm(soc:soc, uid:uid, tid:tid, pipe:pipe);

r2 = registry_get_key(soc:soc, uid:uid, tid:tid, pipe:pipe, key:key, reply:r);
if(r2)
{
 r3 =  registry_get_item_sz(soc:soc, uid:uid, tid:tid, pipe:pipe, item:item, reply:r2);
 registry_close(soc:soc, uid:uid, tid:tid, pipe:pipe, reply:r2);
 registry_close(soc:soc, uid:uid, tid:tid, pipe:pipe, reply:r);
 value = registry_decode_sz(data:r3);
 close(soc);
 return(value);
}
close(soc);
return(FALSE);
}

#---------------------------------------------------------------------------#
# SAM related functions							    #
#---------------------------------------------------------------------------#

#------------------------------------------------------#
# Open a pipe to \samr                                 #
#------------------------------------------------------#
function OpenPipeToSamr(soc, uid, tid)
{
 tid_hi = tid / 256;
 tid_lo = tid % 256;
 
 uid_hi = uid / 256;
 uid_lo = uid % 256;
 
 
 req = raw_string(0x00, 0x00,
 		  0x00, 0x60, 0xFF, 0x53, 0x4D, 0x42, 0xA2, 0x00,
		  0x00, 0x00, 0x00, 0x18, 0x07, 0xC8, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, tid_lo, tid_hi, 0x00, 0x28, uid_lo, uid_hi,
		  g_mlo, g_mhi, 0x18, 0xFF, 0x00, 0xDE, 0xDE, 0x00,
		  0x0A, 0x00, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 
		  0x00, 0x00, 0x9F, 0x01, 0x02, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00,
		  0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x02, 0x00,
		  0x00, 0x00, 0x03, 0x0D, 0x00, 0x00, 0x5C, 0x00,
		  0x73, 0x00, 0x61, 0x00, 0x6D, 0x00, 0x72, 0x00,
		  0x00, 0x00);
		  
		  
 send(socket:soc, data:req);
 r = smb_recv(socket:soc, length:4096);
 if(strlen(r) < 42) return(FALSE);
 else {
 	low = ord(r[42]);
	hi  = ord(r[43]);
	ret = hi * 256;
	ret = ret + low;
	return(ret);
      }
}

function samr_smbwritex(soc, tid, uid, pipe)
{
 tid_hi = tid / 256;
 tid_lo = tid % 256;
 
 uid_hi = uid / 256;
 uid_lo = uid % 256;
 
 pipe_hi = pipe / 256;
 pipe_lo = pipe % 256;
 
 req = raw_string(0x00, 0x00,
 		  0x00, 0x88, 0xFF, 0x53, 0x4D, 0x42, 0x2F, 0x00,
		  0x00, 0x00, 0x00, 0x18, 0x07, 0xC8, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, tid_lo, tid_hi, 0x00, 0x28, uid_lo, uid_hi,
		  g_mlo, g_mhi, 0x0E, 0xFF, 0x00, 0xDE, 0xDE, pipe_lo,
		  pipe_hi, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF,
		  0xFF, 0x08, 0x00, 0x48, 0x00, 0x00, 0x00, 0x48,
		  0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x49,
		  0x00, 0xEE, 0x05, 0x00, 0x0B, 0x03, 0x10, 0x00,
		  0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x01, 0x00,
		  0x00, 0x00, 0xB8, 0x10, 0xB8, 0x10, 0x00, 0x00,
		  0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x01, 0x00, 0x78, 0x57, 0x34, 0x12, 0x34, 0x12,
		  0xCD, 0xAB, 0xEF, 0x00, 0x01, 0x23, 0x45, 0x67,
		  0x89, 0xAC, 0x01, 0x00, 0x00, 0x00, 0x04, 0x5D,
		  0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11, 0x9F, 0xE8,
		  0x08, 0x00, 0x2B, 0x10, 0x48, 0x60, 0x02, 0x00,
		  0x00, 0x00);
		  
 send(socket:soc, data:req);
 r = smb_recv(socket:soc, length:4096);
}		


function samr_smbreadx(soc, tid, uid, pipe)
{
 tid_hi = tid / 256;
 tid_lo = tid % 256;
 uid_hi = uid / 256;
 uid_lo = uid % 256;
 pipe_hi = pipe / 256;
 pipe_lo = pipe % 256;
 req = raw_string(0x00, 0x00,
 		  0x00, 0x3B, 0xFF, 0x53, 0x4D, 0x42, 0x2E, 0x00,
		  0x00, 0x00, 0x00, 0x18, 0x07, 0xC8, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, tid_lo, tid_hi, 0x00, 0x28, uid_lo, uid_hi,
		  g_mlo, g_mhi, 0x0C, 0xFF, 0x00, 0xDE, 0xDE, pipe_lo,
	       pipe_hi, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00,
		  0x04, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x04, 0x00, 
		  0x00, 0x00, 0x00, 0x00, 0x00);
		  
 send(socket:soc, data:req);
 r = smb_recv(socket:soc, length:4096);

}		    

#------------------------------------------------------#
# Returns the unicode representation of <name>         #
#------------------------------------------------------#
function samr_uc(name)
{
 ret = "";
 for(i=0;i<strlen(name);i=i+1)
 {
  ret = ret + raw_string(0) + name[i];
 }
 return(ret);
}



#------------------------------------------------------#
# Connects to the remote SAM                           #
#------------------------------------------------------#
function SamrConnect2(soc, tid, uid, pipe, name)
{
 samr_smbwritex(soc:soc, tid:tid, uid:uid, pipe:pipe);
 samr_smbreadx(soc:soc, tid:tid, uid:uid, pipe:pipe);
 
 l = strlen(name);
 odd = l % 2;
 
 if(odd)p = 0;
 else p = 2;
 
 tid_hi = tid / 256;
 tid_lo = tid % 256;
 uid_hi = uid / 256;
 uid_lo = uid % 256;
 
 pipe_hi = pipe / 256;
 pipe_lo = pipe % 256;
 
 
 l = 3 + strlen(name);
 l_h = l / 256;
 l_l = l % 256;
 

 tot_len = 134 + strlen(name) + strlen(name) + p;
 tot_len_h = tot_len / 256;
 tot_len_l = tot_len % 256;
 
 bcc = 67 + strlen(name) + strlen(name) + p;
 bcc_lo = bcc % 256;
 bcc_hi = bcc / 256;
 
 total_data_count = 50 + strlen(name) + strlen(name) + p;
 total_data_count_lo = total_data_count % 256;
 total_data_count_hi = total_data_count / 256;
 
 req = raw_string(0x00, 0x00,
 		  tot_len_h, tot_len_l, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
		  0x00, 0x00, 0x00, 0x18, 0x07, 0xC8, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, tid_lo, tid_hi, 0x00, 0x28, uid_lo, uid_hi,
		  g_mlo, g_mhi, 0x10, 0x00, 0x00,total_data_count_lo, total_data_count_hi, 0x00,
		  0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54,
		  0x00, total_data_count_lo, total_data_count_hi, 0x54, 0x00, 0x02, 0x00, 0x26,
		  0x00, pipe_lo, pipe_hi, bcc_lo, bcc_hi, 0x00, 0x5C, 0x00,
		  0x50, 0x00, 0x49, 0x00, 0x50, 0x00, 0x45, 0x00,
		  0x5C, 0x00, 0x00, 0x00, 0xAF, 0x47, 0x05, 0x00,
		  0x00, 0x03, 0x10, 0x00, 0x00, 0x00, total_data_count_lo, total_data_count_hi,
		  0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x28, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x39, 0x00, 0x60, 0x60,
		  0x13, 0x00, l_l, l_h, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, l_l, l_h, 0x00, 0x00, 0x5C, 0x00,
		  0x5C) + samr_uc(name:name) + raw_string(0x00, 0x00, 0x00);
		  
  if(p)req = req + raw_string(0xC9, 0x11); # 0x02, 0x00, 0x00, 0x00);
  
  req = req +  raw_string(0x30, 0x00, 0x00, 0x00);
 #display(strlen(req), "\n");		  
 send(socket:soc, data:req);
 r = smb_recv(socket:soc, length:4096);		  
 #display("--->", strlen(r), "\n");
 #
 # We return a handle to the remote SAM
 #		  
 
 samrhdl = "";
 _len = strlen(r);
 if(_len < 24)
 	return(FALSE);
	
 _len = _len - 24;
 for(i=0;i<20;i=i+1)
 {
  samrhdl = samrhdl + raw_string(ord(r[i+_len]));
  #display(hex(ord(r[i+_len])), " ");
 }
 #display("\n");
 #display("samhdl : ", strlen(samrhdl), "\n");
 return(samrhdl);
}


#--------------------------------------------------------------#
# This function is probably SamrEnumerateDomainsInSamServer()  #
# but I'm not sure of that, so I changed its name to           #
# _SamrEnumDomains()                                           #
#                                                              #
# This function only returns the first domain it obtains       #
#--------------------------------------------------------------#
function _SamrEnumDomains(soc, uid, tid, pipe, samrhdl)
{
 tid_hi = tid / 256;
 tid_lo = tid % 256;
 uid_hi = uid / 256;
 uid_lo = uid % 256;
 
 pipe_hi = pipe / 256;
 pipe_lo = pipe % 256;
 
 req = raw_string(0x00, 0x00,
 		  0x00, 0x88, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
		  0x00, 0x00, 0x00, 0x18, 0x07, 0xC8, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, tid_lo, tid_hi, 0x00, 0x28, uid_lo, uid_hi,
		  g_mlo, g_mhi, 0x10, 0x00, 0x00, 0x34, 0x00, 0x00,
		  0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54,
		  0x00, 0x34, 0x00, 0x54, 0x00, 0x02, 0x00, 0x26,
		  0x00, pipe_lo, pipe_hi, 0x45, 0x00, 0x00, 0x5C, 0x00,
		  0x50, 0x00, 0x49, 0x00, 0x50, 0x00, 0x45, 0x00,
		  0x5C, 0x00, 0x00, 0x00, 0xAF, 0x47, 0x05, 0x00,
		  0x00, 0x03, 0x10, 0x00, 0x00, 0x00, 0x34, 0x00,
		  0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x1C, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x06, 0x00) + samrhdl +
	raw_string(0x00, 0x00, 0x00, 0x00, 0x00, 0x20,
		  0x00, 0x00);
		  
 send(socket:soc, data:req);
 r = smb_recv(socket:soc, length:4096);		  
 if(strlen(r) < 137)return(FALSE);
 
 len_lo = ord(r[136]);
 len_hi = ord(r[137]);
 
 len = len_hi * 256;
 len = len + len_lo;
 dom = "";
 len = len*2;
 maxlen = strlen(r);
 if(maxlen < len)return(FALSE);
 for(i=0;i<len;i=i+2)
 {
  if(maxlen < 139+i)return(FALSE);
  dom = dom + raw_string(ord(r[139+i]), ord(r[140+i]));
 }
 #display(dom, "\n");
 return(dom);  
}


#------------------------------------------------------#
# Returns the sid from the domain <dom>                #
#------------------------------------------------------#

function SamrDom2Sid(soc, tid, uid, pipe, samrhdl, dom)
{
 tid_hi = tid / 256;
 tid_lo = tid % 256;
 uid_hi = uid / 256;
 uid_lo = uid % 256;
 
 pipe_hi = pipe / 256;
 pipe_lo = pipe % 256;
 
 #display(strlen(dom), "<-dom\n");
 tot_len = 148 + strlen(dom);
 tot_len_hi = tot_len / 256;
 tot_len_lo = tot_len % 256;
 
 bcc = 81 + strlen(dom);
 bcc_lo = bcc % 256;
 bcc_hi = bcc / 256;
 
 tot_dat_count = 64 + strlen(dom);
 tot_dat_count_lo = tot_dat_count % 256;
 tot_dat_count_hi = tot_dat_count / 256;
 
 dom_len = strlen(dom);
 dom_len = dom_len / 2;
 dom_len_lo = dom_len % 256;
 dom_len_hi = dom_len / 256;
  
 dom_t_len =  dom_len + 1;
 dom_t_len_lo = dom_t_len % 256;
 dom_t_len_hi = dom_t_len / 256;
 
 dom_m_len = dom_len * 2;
 dom_m_len_lo = dom_m_len % 256;
 dom_m_len_hi = dom_m_len / 256;
 
 dom_mm_len = dom_m_len + 2;
 dom_mm_len_lo = dom_mm_len % 256;
 dom_mm_len_hi = dom_mm_len / 256;
 
 
 req = raw_string(0x00, 0x00,
 		 tot_len_hi, tot_len_lo, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
		 0x00, 0x00, 0x00, 0x18, 0x07, 0xC8, 0x00, 0x00,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x00, tid_lo, tid_hi, 0x00, 0x28, uid_lo, uid_hi,
		 g_mlo, g_mhi, 0x10, 0x00, 0x00, tot_dat_count_lo, tot_dat_count_hi, 0x00,
		 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54,
		 0x00, tot_dat_count_lo, tot_dat_count_hi, 0x54, 0x00, 0x02, 0x00, 0x26,
		 0x00, pipe_lo, pipe_hi, bcc_lo, bcc_hi, 0x00, 0x5C, 0x00,
		 0x50, 0x00, 0x49, 0x00, 0x50, 0x00, 0x45, 0x00,
		 0x5C, 0x00, 0x00, 0x00, 0xAF, 0x47, 0x05, 0x00,
		 0x00, 0x03, 0x10, 0x00, 0x00, 0x00, tot_dat_count_lo, tot_dat_count_hi,
		 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x38, 0x00,
		 0x00, 0x00, 0x00, 0x00, 0x05, 0x00) + samrhdl + 
   raw_string(	 dom_m_len_lo, dom_m_len_hi, dom_mm_len_lo, dom_mm_len_hi, 0x40, 0x7B,
   		 0x13, 0x00, dom_t_len_lo, dom_t_len_hi, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x00, dom_len_lo, dom_len_hi, 0x00) + dom + raw_string(0x00);
		 
  send(socket:soc, data:req);
  r = smb_recv(socket:soc, length:4096);
  if(strlen(r) < 88)return(FALSE);
  #display(ord(r[88]), "\n");  
  
  _sid = "";
  
  for(i=0;i<28;i=i+1)
  {
   _sid = _sid + raw_string(ord(r[88+i]));
   #display(hex(ord(r[88+i])),  " ");
  }
  #display("\n");
  return(_sid);
}


#------------------------------------------------------#
# Opens a policy handle to a given domain              #
#------------------------------------------------------#
function SamrOpenDomain(soc, tid, uid, pipe, samrhdl, sid)
{

 #display("sid = ", strlen(sid), "\n");
 tid_hi = tid / 256;
 tid_lo = tid % 256;
 uid_hi = uid / 256;
 uid_lo = uid % 256;
 
 pipe_hi = pipe / 256;
 pipe_lo = pipe % 256;
 
 
 len = 132 + strlen(sid);
 len_h = len / 256;
 len_l = len % 256;

 tdc = 48 + strlen(sid);
 tdc_l = tdc % 256;
 tdc_h = tdc / 256;
 
 bcc = tdc + 17;
 bcc_l = bcc % 256;
 bcc_h = bcc / 256;
 req = raw_string(0x00, 0x00,
 		  0x00, 0xA0, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
		  0x00, 0x00, 0x00, 0x18, 0x07, 0xC8, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, tid_lo, tid_hi, 0x00, 0x28, uid_lo, uid_hi,
		  g_mlo, g_mhi, 0x10, 0x00, 0x00, 0x4C, 0x00, 0x00,
		  0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54,
		  0x00, 0x4C, 0x00, 0x54, 0x00, 0x02, 0x00, 0x26,
		  0x00, pipe_lo, pipe_hi, 0x5D, 0x00, 0x00, 0x5C, 0x00,
		  0x50, 0x00, 0x49, 0x00, 0x50, 0x00, 0x45, 0x00,
		  0x5C, 0x00, 0x00, 0x00, 0x33, 0x00, 0x05, 0x00,
		  0x00, 0x03, 0x10, 0x00, 0x00, 0x00, 0x4C, 0x00,
		  0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x34, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x07, 0x00) + samrhdl +
	raw_string(0x00, 0x02, 0x00, 0x00) + sid;
		  
		  
		  
 send(socket:soc, data:req);
 r = smb_recv(socket:soc, length:4096);
 if(strlen(r) < 30)
 	return(FALSE);
	
 #display(strlen(r),"\n");
 samrhdl = "";
 _len = strlen(r);
 _len = _len - 24;
 _z = 0;
 for(i=0;i<20;i=i+1)
 {
  if(ord(r[i+_len]) == 0)_z = _z + 1;
  samrhdl = samrhdl + raw_string(ord(r[i+_len]));
  #display(hex(ord(r[i+_len])), " ");
 }
 #display("\n");
 #display("samhdl : ", strlen(samrhdl), "\n");
 if(_z == 20)return(NULL);
 
 return(samrhdl);
}		  


#------------------------------------------------------#
# NetUserModalsGet - does not work yet		       #
#------------------------------------------------------#
function SamrQueryDomainInfo(soc, tid, uid, pipe, samrhdl,  level)
{
 #display("sid = ", strlen(sid), "\n");
 tid_hi = tid / 256;
 tid_lo = tid % 256;
 uid_hi = uid / 256;
 uid_lo = uid % 256;
 
 pipe_hi = pipe / 256;
 pipe_lo = pipe % 256;
 
 
 req = raw_string(0x00, 0x00,
 		  0x00, 0x82, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
		  0x00, 0x00, 0x00, 0x18, 0x07, 0xC8, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, tid_lo, tid_hi, 0x00, 0x28, uid_lo, uid_hi,
		  g_mlo, g_mhi, 0x10, 0x00, 0x00, 0x2e, 0x00, 0x00,
		  0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54,
		  0x00, 0x2e, 0x00, 0x54, 0x00, 0x02, 0x00, 0x26,
		  0x00, pipe_lo, pipe_hi, 0x3f, 0x00, 0x00, 0x5C, 0x00,
		  0x50, 0x00, 0x49, 0x00, 0x50, 0x00, 0x45, 0x00,
		  0x5C, 0x00, 0x00, 0x00, 0x45, 0x00, 0x05, 0x00,
		  0x00, 0x03, 0x10, 0x00, 0x00, 0x00, 0x2E, 0x00,
		  0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x16, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x08, 0x00) + samrhdl +
	raw_string(level % 256, level / 256);
		  
		  
		  
 send(socket:soc, data:req);
 r = smb_recv(socket:soc, length:4096);
 if(strlen(r) < 30)
 	return(FALSE);

 return r;	
}		  


function SamrOpenBuiltin(soc, tid, uid, pipe, samrhdl)
{
 tid_hi = tid / 256;
 tid_lo = tid % 256;
 uid_hi = uid / 256;
 uid_lo = uid % 256;
 
 pipe_hi = pipe / 256;
 pipe_lo = pipe % 256;

 req = raw_string(0x00, 0x00,
 		  0x00, 0x94, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
		  0x00, 0x00, 0x00, 0x18, 0x07, 0xC8, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, tid_lo, tid_hi, 0x00, 0x28, uid_lo, uid_hi,
		  g_mlo, g_mhi, 0x10, 0x00, 0x00, 0x40, 0x00, 0x00,
		  0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54,
		  0x00, 0x40, 0x00, 0x54, 0x00, 0x02, 0x00, 0x26,
		  0x00, pipe_lo, pipe_hi, 0x51, 0x00, 0x00, 0x5C, 0x00,
		  0x50, 0x00, 0x49, 0x00, 0x50, 0x00, 0x45, 0x00,
		  0x5C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00,
		  0x00, 0x03, 0x10, 0x00, 0x00, 0x00, 0x40, 0x00,
		  0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x28, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x07, 0x00) + samrhdl +
       raw_string(            0x80, 0x02, 0x00, 0x00, 0x01, 0x00,
       		  0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x05, 0x20, 0x00, 0x00, 0x00);
		  
 send(socket:soc, data:req);
 r = smb_recv(socket:soc, length:4096);
 builtinhdl = "";
 _len = strlen(r);
 _len = _len - 24;
 _z  = 0;
 for(i=0;i<20;i=i+1)
 { 
  if(ord(r[i+_len]) == 0)_z = _z + 1;
  builtinhdl = builtinhdl + raw_string(ord(r[i+_len]));
  #display(hex(ord(r[i+_len])), " ");
 }
 if(_z == 20)return(NULL);
#display("\n");
#display("builtinhdl : ", strlen(builtinhdl), "\n");
 return(builtinhdl);
 
 		  
}


#------------------------------------------------------#
# Converts a username to its rid                       #
#------------------------------------------------------#
function SamrLookupNames(soc, uid, tid, pipe, name, domhdl)
{
 tid_hi = tid / 256;
 tid_lo = tid % 256;
 uid_hi = uid / 256;
 uid_lo = uid % 256;
 
 pipe_hi = pipe / 256;
 pipe_lo = pipe % 256;
 
 usr = samr_uc(name:name);
 len = 164 + strlen(usr);
 len_hi = len / 256;
 len_lo = len % 256;

 
 
 tdc = 80 + strlen(usr);
 tdc_l = tdc % 256;
 tdc_h = tdc / 256;
 
 bcc = tdc + 17;
 bcc_l = bcc % 256;
 bcc_h = bcc / 256;
 
 x = strlen(usr) / 2;
 x_h = x / 256;
 x_l = x % 256;
 
 y = x + 1;
 y_h = y / 256;
 y_l = y % 256;
 
 z = strlen(usr);
 z_l = z % 256;
 z_h = z / 256;
 
 t = z + 2;
 t_l = t % 256;
 t_h = t / 256;
 
 
 req = raw_string(0x00, 0x00, 
 		  len_hi, len_lo, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
		  0x00, 0x00, 0x00, 0x18, 0x07, 0xC8, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, tid_lo, tid_hi, 0x00, 0x28, uid_lo, uid_hi,
		  g_mlo, g_mhi, 0x10, 0x00, 0x00, tdc_l, tdc_h, 0x00,
		  0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54,
		  0x00, tdc_l, tdc_h, 0x54, 0x00, 0x02, 0x00, 0x26,
		  0x00, pipe_lo, pipe_hi, bcc_l, bcc_h, 0x00, 0x5C, 0x00,
		  0x50, 0x00, 0x49, 0x00, 0x50, 0x00, 0x45, 0x00,
		  0x5C, 0x00, 0x00, 0x00, 0xAF, 0x47, 0x05, 0x00,
		  0x00, 0x03, 0x10, 0x00, 0x00, 0x00, tdc_l, tdc_h,
		  0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x44, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x11, 0x00) + domhdl +
		  raw_string(0x01, 0x00, 0x00, 0x00, 0xE8, 0x03,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
		  0x00, 0x00, z_l, z_h, t_l, t_h, 0xD8, 0x0E, 
		  0x41, 0x00, y_l, y_h, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, x_l, x_h, 0x00) + usr + 
		  raw_string(0x00);
 send(socket:soc, data:req);
 r = smb_recv(socket:soc, length:4096);		
 
 if(strlen(r) < 100)return(FALSE);
 
 _rid = "";
##display("RID : ");
 _z = 0;
 for(i=0;i<4;i=i+1)
 {
  if(ord(r[96+i]) == 0)_z = _z + 1;
#  ##display(hex(ord(r[96+i])), " ");
  _rid = _rid + raw_string(ord(r[96+i]));
 }
##display("\n");
 if(_z == 4)return(NULL);
 
 return(_rid);
}

#--------------------------------------------------------#
# Opens a policy handle to a given user                  #
#--------------------------------------------------------#
function SamrOpenUser(soc, uid, tid, pipe, samrhdl, rid)
{
 tid_hi = tid / 256;
 tid_lo = tid % 256;
 uid_hi = uid / 256;
 uid_lo = uid % 256;
 
 pipe_hi = pipe / 256;
 pipe_lo = pipe % 256;
 
 len = 176;
 len_hi = len / 256;
 len_lo = len % 256;
 
 req = raw_string(0x00, 0x00,
 		  0x00, 0x88, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
		  0x00, 0x00, 0x00, 0x18, 0x07, 0xC8, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, tid_lo, tid_hi, 0x00, 0x28, uid_lo, uid_hi,
		  g_mlo, g_mhi, 0x10, 0x00, 0x00, 0x34, 0x00, 0x00,
		  0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54,
		  0x00, 0x34, 0x00, 0x54, 0x00, 0x02, 0x00, 0x26,
		  0x00, pipe_lo, pipe_hi, 0x45, 0x00, 0x00, 0x5C, 0x00,
		  0x50, 0x00, 0x49, 0x00, 0x50, 0x00, 0x45, 0x00,
		  0x5C, 0x00, 0x00, 0x00, 0x33, 0x00, 0x05, 0x00,
		  0x00, 0x03, 0x10, 0x00, 0x00, 0x00, 0x34, 0x00,
		  0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x1c, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x22, 0x00) + samrhdl +
	raw_string(0x1B, 0x01, 0x02, 0x00) + rid;

 send(socket:soc, data:req);
 r = smb_recv(socket:soc, length:4096);
 if(strlen(r) < 100)return(FALSE);
 
 _usrhdl = "";
 _len = strlen(r);
 _len = _len - 24;
 #display("usrhdl = ");
 _z = 0;
 for(i=0;i<20;i=i+1)
 {
  if(ord(r[i+_len]) == 0)_z = _z + 1;
  _usrhdl = _usrhdl + raw_string(ord(r[i+_len]));
  #display(hex(ord(r[i+_len])), " ");
 }
 
 if(_z == 20)return(NULL);
 
 #display("\n");
 return(_usrhdl);
}

#-------------------------------------------------------#
# Requests the list of groups to which the user belongs #
# to						        #
#-------------------------------------------------------#

function SamrQueryUserGroups(soc, uid, tid, pipe, usrhdl)
{
 tid_hi = tid / 256;
 tid_lo = tid % 256;
 uid_hi = uid / 256;
 uid_lo = uid % 256;
 
 pipe_hi = pipe / 256;
 pipe_lo = pipe % 256;
 
 req = raw_string(0x00, 0x00,
 		  0x00, 0x80, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
		  0x00, 0x00, 0x00, 0x18, 0x07, 0xC8, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, tid_lo, tid_hi, 0x00, 0x28, uid_lo, uid_hi,
		  g_mlo, g_mhi, 0x10, 0x00, 0x00, 0x2C, 0x00, 0x00,
		  0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54,
		  0x00, 0x2C, 0x00, 0x54, 0x00, 0x02, 0x00, 0x26, 
		  0x00, pipe_lo, pipe_hi, 0x3D, 0x00, 0x00, 0x5C, 0x00,
		  0x50, 0x00, 0x49, 0x00, 0x50, 0x00, 0x45, 0x00,
		  0x5C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00,
		  0x00, 0x03, 0x10, 0x00, 0x00, 0x00, 0x2C, 0x00,
		  0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x14, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x27, 0x00) + usrhdl;
		  
 send(socket:soc, data:req);
 r = recv(socket:soc, length:4096); 
 
 
 num_lo = ord(r[88]);
 num_hi = ord(r[89]);
 
 num = num_hi * 256;
 num = num + num_lo;
 
 #
 # Ok. Our user is in <num> groups. Let's decode their RID
 #
 
 if(strlen(r) < 103)
 	return(FALSE);
 base = 100;
 rids = "";
 for(i=0;i<num;i=i+1)
 {
  g_rid = string(hex(ord(r[base+3])), "-", 
  	       hex(ord(r[base+2])), "-",
	       hex(ord(r[base+1])), "-",
	       hex(ord(r[base])));
	   
  base = base + 8;
  rids = rids + g_rid + string("\n");
 }	
  return(rids);
}
#------------------------------------------------------#
# Queries information about a given user               #
#------------------------------------------------------#
function SamrQueryUserInfo(soc, uid, tid, pipe, usrhdl)
{
 tid_hi = tid / 256;
 tid_lo = tid % 256;
 uid_hi = uid / 256;
 uid_lo = uid % 256;
 
 pipe_hi = pipe / 256;
 pipe_lo = pipe % 256;
 
 req = raw_string(0x00, 0x00,
 		  0x00, 0x82, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
		  0x00, 0x00, 0x00, 0x18, 0x07, 0xC8, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, tid_lo, tid_hi, 0x00, 0x28, uid_lo, uid_hi,
		  g_mlo, g_mhi, 0x10, 0x00, 0x00, 0x2E, 0x00, 0x00,
		  0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54,
		  0x00, 0x2E, 0x00, 0x54, 0x00, 0x02, 0x00, 0x26,
		  0x00, pipe_lo, pipe_hi, 0x3F, 0x00, 0x00, 0x5C, 0x00,
		  0x50, 0x00, 0x49, 0x00, 0x50, 0x00, 0x45, 0x00,
		  0x5C, 0x00, 0x00, 0x00, 0x33, 0x00, 0x05, 0x00,
		  0x00, 0x03, 0x10, 0x00, 0x00, 0x00, 0x2E, 0x00,
		  0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x16, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x24, 0x00) + usrhdl +
		  raw_string(0x15, 0x00);
		  
 send(socket:soc, data:req);
 r = smb_recv(socket:soc, length:4096);
 		  
 return(r);
}


#-------------------------------------------------------#
# Requests the list of aliases to which the user belongs #
# to						        #
#-------------------------------------------------------#


function SamrQueryUserAliases(soc, uid, tid, pipe, usrhdl, sid, rid)
{
 tid_hi = tid / 256;
 tid_lo = tid % 256;
 uid_hi = uid / 256;
 uid_lo = uid % 256;
 
 pipe_hi = pipe / 256;
 pipe_lo = pipe % 256;
 
 subsid = "";
 
 for(i=0;i<20;i=i+1)
 {
  subsid = subsid + raw_string(ord(sid[8+i]));
  #display(hex(ord(sid[8+i])), " ");
 }
 #display("\n");
 
 
 
 
 req = raw_string(0x00, 0x00, 
 		  0x00, 0xB0, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
		  0x00, 0x00, 0x00, 0x18, 0x07, 0xC8, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, tid_lo, tid_hi, 0x00, 0x28, uid_lo, uid_hi,
		  g_mlo, g_mhi, 0x10, 0x00, 0x00, 0x5C, 0x00, 0x00,
		  0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54,
		  0x00, 0x5C, 0x00, 0x54, 0x00, 0x02, 0x00, 0x26,
		  0x00, pipe_lo, pipe_hi, 0x6D, 0x00, 0x00, 0x5C, 0x00,
		  0x50, 0x00, 0x49, 0x00, 0x50, 0x00, 0x45, 0x00,
		  0x5C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00,
		  0x00, 0x03, 0x10, 0x00, 0x00, 0x00, 0x5C, 0x00,
		  0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x44, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x10, 0x00) + usrhdl +
       raw_string(0x01, 0x00, 0x00, 0x00, 0x88, 0x7C,
       	 	  0x13, 0x00, 0x01, 0x00, 0x00, 0x00, 0x98, 0x7C,
		  0x13, 0x00, 0x05, 0x00, 0x00, 0x00, 0x01, 0x05,
		  0x00, 0x00) + subsid + rid;
		  
 send(socket:soc, data:req);
 r = smb_recv(socket:soc, length:4096);
 
 if(strlen(r) < 100){
 	#display("=====>", strlen(r), "<====\n");
 	return(FALSE);
	}
 
 
 num_lo = ord(r[92]);
 num_hi = ord(r[93]);
 
 num = num_hi * 256;
 num = num + num_lo;
 #display("NUM EGAL : ", num, "\n");
 base = 96;
 rids = "";
 for(i=0;i<num;i=i+1)
 {
  _rid = string(hex(ord(r[base+3])), "-",
  		hex(ord(r[base+2])), "-",
		hex(ord(r[base+1])), "-",
		hex(ord(r[base])));
		
  rids = rids + _rid + string("\n");		
  base = base + 4;		
 }	  
 return(rids);
}		


function _ExtractTime(buffer, base)
{
if (strlen(buffer) < base + 8) return(FALSE);

 return(string(      hex(ord(buffer[base+7])), "-",
 		     hex(ord(buffer[base+6])), "-",
		     hex(ord(buffer[base+5])), "-",
		     hex(ord(buffer[base+4])), "-",
		     hex(ord(buffer[base+3])), "-",
		     hex(ord(buffer[base+2])), "-",
		     hex(ord(buffer[base+1])), "-",
		     hex(ord(buffer[base]))));
}


#------------------------------------------------------#
# Decodes the informations received about a given usr  #
# This function is not part of MSDN, hence the under-  #
# score in front of it                                 #
#------------------------------------------------------#

function _SamrDecodeUserInfo(info, count, type)
{
 lim = strlen(info);
 
 

 if(strlen(info) < 100)
 	return(FALSE);
	

 #
 # Various times
 #
 
 logon = _ExtractTime(buffer:info, base:92);
 #display("Logon time : ", logon, "\n");
 
 set_kb_item(name:string("SMB/", type, "/", count, "/Info/LogonTime"),
 	     value:logon);
	     
 
 logoff = _ExtractTime(buffer:info, base:100);
 #display("Logoff time : ", logoff, "\n");
  set_kb_item(name:string("SMB/", type, "/", count, "/Info/LogoffTime"),
 	     value:logoff);

 if(strlen(info) < 116)
 	return(FALSE);
 

 kickoff = _ExtractTime(buffer:info, base:108);
 #display("Kickoff time : ", kickoff, "\n");
  set_kb_item(name:string("SMB/", type, "/", count, "/Info/KickoffTime"),
 	     value:kickoff);
	     
 base = 116;
 pass_last_set = _ExtractTime(buffer:info, base:116);

 if(strlen(info) < 124)
 	return(FALSE);
 

 #display("Pass last set : ", pass_last_set, "\n");		     
 set_kb_item(name:string("SMB/", type, "/", count, "/Info/PassLastSet"),
 	     value:pass_last_set); 
	     
	     
 pass_can_change = _ExtractTime(buffer:info, base:124);
 #display("Pass can change : ", pass_can_change,"\n");
  set_kb_item(name:string("SMB/", type, "/", count, "/Info/PassCanChange"),
 	     value:pass_can_change);
 
 pass_must_change = _ExtractTime(buffer:info, base:132);
 
 #display("Pass must change : ", pass_must_change, "\n");
  set_kb_item(name:string("SMB/", type, "/", count, "/Info/PassMustChange"),
 	     value:pass_must_change);
 
 #
 # ACB
 #
 
 if(strlen(info) < 260)
 {
  return(FALSE);
 }
 
 acb_lo = ord(info[260]);
 acb_hi = ord(info[261]);
 acb = acb_hi * 256;
 acb = acb + acb_lo;
 #display("ACB : ", hex(acb), "\n");
 
  set_kb_item(name:string("SMB/", type, "/", count, "/Info/ACB"),
 	     value:acb);
	     
	     
 #if(acb & 0x01)display("  Account is disabled\n");
 #if(acb & 0x04)display("  Password not required\n");
 #if(acb & 0x10)display("  Normal account\n");
 #if(acb & 0x0200)display("  Password does not expire\n");
 #if(acb & 0x0400)display("  Account auto-locked\n");
 #if(acb & 0x0800)display("  Password can't be changed\n");
  
 #if(acb & 0x1000)display("  Smart card is required for interactive log on\n");
 #if(acb & 0x2000)display("  Account is trusted for delegation\n");
 #if(acb & 0x4000)display("  Account is sensitive an can not be delegated\n");
 #if(acb & 0x8000)display("  Use DES encryption type for this account\n");
 
}



#-------------------------------------------------------------------#



#
# Open file <file>
#
function OpenAndX(socket, uid, tid, file)
{
 local_var req, tid_lo, tid_hi, uid_lo, uid_hi, len_lo, len_hi, rep;
 local_var fid_lo, fid_hi;
 
 
 len_lo = (66 + strlen(file)) % 256;
 len_hi = (66 + strlen(file)) / 256;
 
 tid_lo = tid % 256;
 tid_hi = tid / 256;
 
 uid_lo = uid % 256;
 uid_hi = uid / 256;
 
 bcc_lo = strlen(file) % 256;
 bcc_hi = strlen(file) / 256;
 
 
 req = raw_string(0x00, 0x00, len_hi, len_lo,   0xFF, 0x53,
 		  0x4D, 0x42, 0x2D, 0x00, 0x00, 0x00, 0x00, 0x08,
		  0x01, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, tid_lo, tid_hi,
		  0x00, 0x28, uid_lo, uid_hi, g_mlo, g_mhi, 0x0F, 0xFF,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x06,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, bcc_lo, bcc_hi) + file +
		  raw_string(0x00);



 send(socket:socket, data:req);
 rep = smb_recv(socket:socket, length:4096);
 if(strlen(rep) < 65)return(NULL);
 else
  {
   fid_lo = ord(rep[41]);
   fid_hi = ord(rep[42]);
   
   return(fid_lo + (fid_hi * 256));
  }
}


#
# Read <count> bytes at offset <off>
#
function ReadAndX(socket, uid, tid, fid, count, off)
{
 local_var r, req, uid_lo, uid_hi, tid_lo, tid_hi, fid_lo, fid_hi, off_hi, off_lo, ret, i;
 
 uid_lo = uid % 256; uid_hi = uid / 256;
 tid_lo = tid % 256; tid_hi = tid / 256;
 fid_lo = fid % 256; fid_hi = fid / 256;
 cnt_lo = count % 256; cnt_hi = count / 256;
 
 off_lo_lo = off % 256;  off /= 256;
 off_lo_hi = off % 256;  off /= 256;
 off_hi_lo = off % 256;  off /= 256;
 off_hi_hi = off;
 
 req = raw_string(0x00, 0x00, 0x00, 0x37, 0xFF, 0x53,
 		  0x4D, 0x42, 0x2E, 0x00, 0x00, 0x00, 0x00, 0x08,
		  0x01, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, tid_lo, tid_hi,
		  0x00, 0x28, uid_lo, uid_hi, g_mlo, g_mhi, 0x0A, 0xFF,
		  0x00, 0x00, 0x00, fid_lo, fid_hi, off_lo_lo, off_lo_hi, off_hi_lo, 
		  off_hi_hi, cnt_lo, cnt_hi, cnt_lo, cnt_hi, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
 
 send(socket:socket, data:req);
 r = smb_recv(socket:socket, length:65535);
 ret = "";
 if(strlen(r) < 37 + 28)return(NULL);
 return substr(r, 36+28, strlen(r) - 1);	   
}


# Returns the size of the file pointed by <fid>
function smb_get_file_size(socket, uid, tid, fid)
{
 local_var r, req, uid_lo, uid_hi, tid_lo, tid_hi, fid_lo, fid_hi, ret;
 
 uid_lo = uid % 256; uid_hi = uid / 256;
 tid_lo = tid % 256; tid_hi = tid / 256;
 fid_lo = fid % 256; fid_hi = fid / 256;
 
 
 req = raw_string(0x00, 0x00, 0x00, 0x48, 0xFF, 0x53,
 		  0x4D, 0x42, 0x32, 0x00, 0x00, 0x00, 0x00, 0x08,
		  0x01, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, tid_lo, tid_hi,
		  0x00, 0x28, uid_lo, uid_hi, g_mlo, g_mhi, 0x0F, 0x04,
		  0x00, 0x00, 0x00, 0x02, 0x00, 0x04, 0x11, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x04, 0x00, 0x44, 0x00, 0x00, 0x00, 0x48,
		  0x00, 0x01, 0x00, 0x07, 0x00, 0x07, 0x00, 0x00,
		  0x44, 0x20, fid_lo, fid_hi, 0x07, 0x01);
		  
 send(socket:socket, data:req);
 r = smb_recv(socket:socket, length:4096);
 if(strlen(r) < 112) return -1;
 
 ret = ord(r[115]);			
 ret = ret * 256 + ord(r[114]);		
 ret = ret * 256 + ord(r[113]);
 ret = ret * 256 + ord(r[112]);		
 
 return ret;
}

#
# Gives the listing in the pattern <pattern> 
# If pattern is set to NULL, then we return the
# content of the root (\*)
#
function FindFirst2(socket, uid, tid, pattern)
{
 local_var uid_lo, uid_hi, tid_lo, tid_hi, r, r2;
 local_var t, nxt, off, name, ret, bcc, bcc_lo, bcc_hi;
 local_var len, len_lo, len_hi;
 local_var unicode_pattern, i;
 local_var data_off, data_off_lo, data_off_hi, bcc2, bcc2_lo, bcc2_hi;
 local_var eof, search_id, err;
 
 
 if(isnull(pattern))pattern = "\*";
 
 for(i=0;i<strlen(pattern);i++)
 {
  unicode_pattern += pattern[i] + raw_string(0);
 }
 unicode_pattern += raw_string(0, 0);
 
 
 ret = NULL;
 
  
 bcc = 15 + strlen(unicode_pattern);
 bcc2 = bcc - 3;
 len    = 80 + strlen(unicode_pattern);
 
 uid_lo = uid % 256; uid_hi = uid / 256;
 tid_lo = tid % 256; tid_hi = tid / 256;
 bcc_lo = bcc % 256; bcc_hi = bcc / 256;
 bcc2_lo = bcc2 % 256; bcc2_hi = bcc2 / 256;
 len_lo = len % 256; len_hi = len / 256;
 
 data_off = 80 + strlen(unicode_pattern);
 data_off_lo = data_off % 256; data_off_hi = data_off / 256;
 
 req = raw_string(0x00, 0x00, len_hi, len_lo,   0xFF, 0x53,
 		  0x4D, 0x42, 0x32, 0x00, 0x00, 0x00, 0x00, 0x08,
 		  0x01, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, tid_lo, tid_hi,
		  0x00, 0x28, uid_lo, uid_hi, g_mlo, g_mhi, 0x0F, bcc2_lo,
		  bcc2_hi, 0x00, 0x00, 0x0A, 0x00, 0x04, 0x11, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, bcc2_lo, bcc2_hi, 0x44, 0x00, 0x00, 0x00, data_off_lo,
		  data_off_hi, 0x01, 0x00, 0x01, 0x00, bcc_lo, bcc_hi, 0x00,
		  0x44, 0x20, 0x16, 0x00, 0x00, 0x02, 0x06, 0x00,
		  0x04, 0x01, 0x00, 0x00, 0x00, 0x00) + unicode_pattern;

 send(socket:soc, data:req);
 r = smb_recv(socket:soc, length:65535);
 if(strlen(r) < 80)return(NULL);

 err = substr(r, 11, 12);
 if ( hexstr(err) != "0000" ) return NULL;
 
 search_id = substr(r, 60, 61);
 off = 72;
 while ( TRUE )
 {
 eof = ord(r[64]);
 while(TRUE)
 {
 t = 1;
 nxt = 0;
 
 if(off + i + 4 >= strlen(r))break;
 
 for(i=0;i<4;i++)
 {
 nxt += ord(r[off+i]) * t;
 t *= 256;
 }
 
 
 
 t = 1;
 len = 0;
 
 if( off+4+4+8+8+8+8+8+8+4+i+4 >= strlen(r))break;
 
 for(i=0;i<4;i++)
 {
 len += ord(r[off+4+4+8+8+8+8+8+8+4+i]) * t;
 t *= 256;
 }


 if(len >= strlen(r)) break;
	
 
 name = NULL;
 
 if(off+4+4+8+8+8+8+8+8+4+4+1+1+24+i+len >  strlen(r)) 
	 break;

 for(i=0;i<len;i+=2)
 {
 name += r[off+4+4+8+8+8+8+8+8+4+4+4+1+1+24+i];
 }
 
 if( !isnull(name))
 {
 if(isnull(ret))
   	ret = make_list(name);
 else
 	ret = make_list(ret, name);
 }
 
 off = off + nxt;
 if(nxt == 0)break;
 if((off >= strlen(r)) || off < 0 )return ret;
 }
  if ( eof ) break;
  else {
    req = raw_string(0x00, 0x00, 0x00, 0x52, 0xff, 0x53, 0x4d, 0x42,
		     0x32, 0x00, 0x00, 0x00, 0x00, 0x08, 0x01, 0xC0,
		     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		     0x00, 0x00, 0x00, 0x00, tid_lo, tid_hi, 0x00, 0x28,
		     uid_lo, uid_hi, g_mlo, g_mhi, 0x0f, 0x0e, 0x00, 0x00,
		     0x00, 0x0a, 0x00, 0x04, 0x11, 0x00, 0x00, 0x00, 
		     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e,
		     0x00, 0x44, 0x00, 0x00, 0x00, 0x52, 0x00, 0x01,
		     0x00, 0x02, 0x00, 0x11, 0x00, 0x00, 0x44, 0x20) + search_id + raw_string(0x00, 0x02, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00);

  send(socket:soc, data:req);
  r = smb_recv(socket:soc, length:65535);
  err = substr(r, 11, 12);
  if ( hexstr(err) != "0000" ) return NULL;
  if ( strlen(r) <= 64  && hexstr(substr(r, 9, 12)) == "00000000" ) r = smb_recv(socket:soc, length:65535);
  else if ( strlen(r) <= 64 ) break;
  off = 68;
  }
 }

 return ret;
}





function GetFileVersion(socket, uid, tid, fid)
{
 local_var i, fsize, data, off, tmp, version, v, len;

 fsize = smb_get_file_size(socket:socket, uid:uid, tid:tid, fid:fid);
 if  ( fsize < 720896 ) 
	off = 0;
 else 
	off = fsize - 720896 ;


 for ( i = 0 ; off < fsize ; i ++ )
 {
   tmp = ReadAndX(socket:soc, uid:uid, tid:tid, fid:fid, count:16384, off:off); 
   tmp = str_replace(find:raw_string(0), replace:"", string:tmp);
   data += tmp;
   version = strstr(data, "ProductVersion");
   if ( version )
   {
     len = strlen(version);
     for(i=strlen("ProductVersion");i<len;i++)
     {
      if((ord(version[i]) < ord("0") || ord(version[i]) > ord("9")) && version[i] != ".")
	return (v);
      else 
        v += version[i];
     }
   }
   off += 16384;
 }

 return NULL;
}

