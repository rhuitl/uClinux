#
# (C) 2004 Tenable Network Security
# 
# $Id: smb_file_funcs.inc,v 1.2 2004/03/14 23:31:07 renaud Exp $
#


# Example usage:
# foobar = smb_file_read(file:"\winnt\system32\foobar.ini", count:512);
# would read first 512 bytes of foobar.ini on the remote system
# the only required parameter is 'file'.  offset will default to 0
# and count will default to 512 bytes

# return values
# file data on success
# ERROR : COULD NOT READ REGISTRY
# ERROR : NEED FILE NAME
# ERROR : PORT DEAD 
# ERROR : NO SOCKET 
# ERROR : NO SMB SESSION REQUEST 
# ERROR : SMB NEGOTIATE PROTOCOL FAILED
# ERROR : SMB SESSION SETUP FAILED
# ERROR : COULD NOT EXTRACT TID
# ERROR : FAILED OpenAndX
# ERROR : MATCHSTRING NOT FOUND

function smb_file_read(file, offset,  count) {
    local_var rootfile, share;
    local_var name, login, pass, domain, port, soc;
    local_var r, prot, uid, tid, fid, fsize, data, v;

    if (!file) return("ERROR : NEED FILE NAME");
    if (!offset) offset = 0;
    if (!count) count = 1024;

    if (egrep(string:file, pattern:"^[a-zA-Z]:.*"))  rootfile = file;
    else 
    {
    rootfile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"ProgramFilesDir");
    }

    if(!rootfile) {
        return("ERROR : COULD NOT READ REGISTRY"); 
    } else {
        share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rootfile);
    }

    if (egrep(string:file, pattern:"^[a-zA-Z]:.*")) file = strstr(file, "\"); 

    name   =  kb_smb_name();
    login  =  kb_smb_login();
    pass   =  kb_smb_password();
    domain =  kb_smb_domain();
    port   =  kb_smb_transport();
    if (!port) port = 139;

    if(!get_port_state(port)) return("ERROR : PORT DEAD");
    soc = open_sock_tcp(port);
    if(!soc) return("ERROR : NO SOCKET");

    if ( port == 139 ) 
    {
     r = smb_session_request(soc:soc, remote:name);
     if(!r) return("ERROR : NO SMB SESSION REQUEST");
    }

    prot = smb_neg_prot(soc:soc);
    if(!prot) return("ERROR : SMB NEGOTIATE PROTOCOL FAILED");

    r = smb_session_setup(soc:soc, login:login, password:pass, domain:domain, prot:prot);
    if(!r) return ("ERROR : SMB SESSION SETUP FAILED");

    uid = session_extract_uid(reply:r);

    r = smb_tconx(soc:soc, name:name, uid:uid, share:share);
    tid = tconx_extract_tid(reply:r);
    if(!tid) return ("ERROR : COULD NOT EXTRACT TID");

    fid = OpenAndX(socket:soc, uid:uid, tid:tid, file:file);
    if(!fid) return("ERROR : FAILED OpenAndX"); 

    fsize = smb_get_file_size(socket:soc, uid:uid, tid:tid, fid:fid);
    if (!fsize) {
        # important to differentiate between -1 and 0
        myret = string("ERROR : FSIZE RETURNED ", fsize);
        return(myret);
    } 

    data = ReadAndX(socket:soc, uid:uid, tid:tid, count:count, off:offset);
    return data;
}
