#
# This script was written by Georges Dagousset <georges.dagousset@alert4web.com>
# HTTP code comes from http_auth.nasl written by Michel Arboi <arboi@alussinan.org>
# NNTP was added by Michel Arboi <arboi@alussinan.org>
#
# See the Nessus Scripts License for details
#


MAX_ADDITIONAL_SMB_LOGINS = 3;

default_http_login = "";
default_http_password = "";

default_nntp_login = "";
default_nntp_password = "";

default_ftp_login = "anonymous";
default_ftp_password = "nessus@nessus.org";
default_ftp_w_dir = "/incoming";

default_pop2_login = "";
default_pop2_password = "";

default_pop3_login = "";
default_pop3_password = "";

default_imap_login = "";
default_imap_password = "";

default_smb_login = "";
default_smb_password = "";
default_smb_domain = "";


if(description)
{
 script_id(10870);
 script_version ("$Revision: 1.23 $");
 name["english"] = "Login configurations";
 name["francais"] = "Configuration des logins";
 
 script_name(english:name["english"],
            francais:name["francais"]);
 
 desc["english"] = "
Provide the username/password for the common servers :
 HTTP, FTP, NNTP, POP2, POP3,IMAP and SMB (NetBios).

Some plugins will use those logins when needed.
If you do not fill some logins, those plugins will not be able run.

This plugin does not do any security check.

Risk factor : None";

 desc["francais"] = "
Fournir le nom_d_utilisateur/mot_de_passe pour les serveurs communs :
 HTTP, FTP, NNTP, POP2, POP3, IMAP et SMB (NetBios).

Certains plugins utiliseront ces logins si nécessaire.
Si vous ne remplissez pas certains logins, ces plugins ne pourront pas s exécuter.

Ce plugin ne fait aucun test de securité

Facteur de risque : Aucun";

 script_description(english:desc["english"],
                   francais:desc["francais"]);
 
 summary["english"] = "Logins for HTTP, FTP, NNTP, POP2, POP3, IMAP and SMB";
 summary["francais"] = "Logins pour HTTP, FTP, NNTP, POP2, POP3, IMAP et SMB";
 script_summary(english:summary["english"],
               francais:summary["francais"]);
 
 script_category(ACT_SETTINGS);
 
 script_copyright(english:"This script is Copyright (C) 2002 Georges Dagousset ");
 family["english"] = "Settings";
 family["francais"] = "Configuration";
 script_family(english:family["english"], francais:family["francais"]);
 
 script_add_preference(name:"HTTP account :", type:"entry", value:default_http_login);
 script_add_preference(name:"HTTP password (sent in clear) :", type:"password", value:default_http_password);

 script_add_preference(name:"NNTP account :", type:"entry", value:default_nntp_login);
 script_add_preference(name:"NNTP password (sent in clear) :", type:"password", value:default_nntp_password);

 script_add_preference(name:"FTP account :", type:"entry", value:default_ftp_login);
 script_add_preference(name:"FTP password (sent in clear) :", type:"password", value:default_ftp_password);
 script_add_preference(name:"FTP writeable directory :", type:"entry", value:default_ftp_w_dir);

 script_add_preference(name:"POP2 account :", type:"entry", value:default_pop2_login);
 script_add_preference(name:"POP2 password (sent in clear) :", type:"password", value:default_pop2_password);

 script_add_preference(name:"POP3 account :", type:"entry", value:default_pop3_login);
 script_add_preference(name:"POP3 password (sent in clear) :", type:"password", value:default_pop3_password);

 script_add_preference(name:"IMAP account :", type:"entry", value:default_imap_login);
 script_add_preference(name:"IMAP password (sent in clear) :", type:"password", value:default_imap_password);

 script_add_preference(name:"SMB account :", type:"entry", value:default_smb_login);
 script_add_preference(name:"SMB password :", type:"password", value:default_smb_password);
 script_add_preference(name:"SMB domain (optional) :", type:"entry", value:default_smb_domain);

 for ( i = 1 ; i <= MAX_ADDITIONAL_SMB_LOGINS ; i ++ )
 {
 script_add_preference(name:"Additional SMB account (" + i + ") :", type:"entry", value:default_smb_login);
 script_add_preference(name:"Additional SMB password (" + i + ") :", type:"password", value:default_smb_password);
 script_add_preference(name:"Additional SMB domain (optional) (" + i + ") :", type:"entry", value:default_smb_password);
 }


 if(defined_func("MD5")) script_add_preference(name:"Never send SMB credentials in clear text", type:"checkbox", value:"yes");
 if(defined_func("MD5")) script_add_preference(name:"Only use NTLMv2", type:"checkbox", value:"no");
 exit(0);
}

include("misc_func.inc");

# HTTP
http_login = script_get_preference("HTTP account :");
http_password = script_get_preference("HTTP password (sent in clear) :");
if (http_login)
{
 if(http_password)
 {
  set_kb_item(name:"http/login", value:http_login);
  set_kb_item(name:"http/password", value:http_password);

  userpass = string(http_login, ":",http_password);
  #display(userpass);
  userpass64 = base64(str:userpass);
  authstr = "Authorization: Basic " + userpass64;
  set_kb_item(name:"http/auth", value:authstr);
 }
}

# NNTP
nntp_login = script_get_preference("NNTP account :");
nntp_password = script_get_preference("NNTP password (sent in clear) :");
if (nntp_login)
{
 if(nntp_password)
 {
  set_kb_item(name:"nntp/login", value:nntp_login);
  set_kb_item(name:"nntp/password", value:nntp_password);
 }
}

# FTP
ftp_login = script_get_preference("FTP account :");
ftp_password = script_get_preference("FTP password (sent in clear) :");
ftp_w_dir = script_get_preference("FTP writeable directory :");
if (!ftp_w_dir) ftp_w_dir=".";
set_kb_item(name:"ftp/writeable_dir", value:ftp_w_dir);
if(ftp_login)
{
 if(ftp_password)
 {
  set_kb_item(name:"ftp/login", value:ftp_login);
  set_kb_item(name:"ftp/password", value:ftp_password);
 }
}

# POP2
pop2_login = script_get_preference("POP2 account :");
pop2_password = script_get_preference("POP2 password (sent in clear) :");
if(pop2_login)
{
 if(pop2_password)
 {
  set_kb_item(name:"pop2/login", value:pop2_login);
  set_kb_item(name:"pop2/password", value:pop2_password);
 }
}

# POP3
pop3_login = script_get_preference("POP3 account :");
pop3_password = script_get_preference("POP3 password (sent in clear) :");
if(pop3_login)
{
 if(pop3_password)
 {
  set_kb_item(name:"pop3/login", value:pop3_login);
  set_kb_item(name:"pop3/password", value:pop3_password);
 }
}

# IMAP
imap_login = script_get_preference("IMAP account :");
imap_password = script_get_preference("IMAP password (sent in clear) :");
if(imap_login)
{
 if(imap_password)
 {
  set_kb_item(name:"imap/login", value:imap_login);
  set_kb_item(name:"imap/password", value:imap_password);
 }
}

# SMB
smb_login = script_get_preference("SMB account :");
if(!smb_login)smb_login = "";

smb_password = script_get_preference("SMB password :");
if(!smb_password)smb_password = "";

smb_domain = script_get_preference("SMB domain (optional) :");
if(!smb_domain)smb_domain = "";

if(defined_func("MD5"))
{
smb_ctxt = script_get_preference("Never send SMB credentials in clear text");
if(!smb_ctxt)smb_ctxt = "yes";
} else smb_ctxt = "no";

if(smb_ctxt == "yes")
 set_kb_item(name:"SMB/dont_send_in_cleartext", value:TRUE);



if(defined_func("MD5"))
{
 smb_ntv1 = script_get_preference("Only use NTLMv2");
 if(smb_ntv1 == "yes"){
 	set_kb_item(name:"SMB/dont_send_ntlmv1", value:TRUE);
	if(smb_ctxt != "yes")set_kb_item(name:"SMB/dont_send_in_cleartext", value:TRUE);
	}
}


if(smb_login)
{
  set_kb_item(name:"SMB/login_filled/0", value:smb_login);
}
  
if(smb_password)
{
  set_kb_item(name:"SMB/password_filled/0", value:smb_password);
}

if(smb_domain)
{ 
 set_kb_item(name:"SMB/domain_filled/0", value:smb_domain);
}

for ( i = 1 ; i <= MAX_ADDITIONAL_SMB_LOGINS ; i ++ )
{
 l = script_get_preference("Additional SMB account (" + i + ") :");
 p = script_get_preference("Additional SMB password (" + i + ") :");
 d = script_get_preference("Additional SMB domain (optional) (" + i + ") :");
 if ( l ) set_kb_item(name:"SMB/login_filled/" + i, value:l);
 if ( p ) set_kb_item(name:"SMB/password_filled/" + i, value:p);
 if ( d ) set_kb_item(name:"SMB/domain_filled/" + i, value:d);
 if ( l || p ) j ++;
}
