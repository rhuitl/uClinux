# By John Lampe
# $Id: uddi.inc,v 1.2 2002/10/09 15:17:56 renaud Exp $

function create_uddi_xml (ktype,path,key,name) 
{
    envelope_header = string("<?xml version='1.0' encoding='UTF-8'?> <s:Envelope");
    envelope_header = string(envelope_header, " xmlns:s='http://schemas.xmlsoap.org/soap/envelope/'><s:Body>");

    get_servicedetail = string("<get_serviceDetail generic='1.0' xmlns='urn:uddi-org:api'>"); 
    get_servicedetail = string(get_servicedetail, "<serviceKey>", key, "</serviceKey></get_serviceDetail>");

    find_business = string("<find_business generic='1.0' xmlns='urn:uddi-org:api'>");
    find_business = string(find_business, "<name>",name,"</name></find_business>");

    find_service = string("<find_service generic='1.0' xmlns='urn:uddi-org:api' businessKey='",key, "'>");
    find_service = string(find_service, "<name>", name, "</name></find_service>");

    close_envelope = string("</s:Body></s:Envelope>");

    if (ktype == "UDDI_QUERY_FBUSINESS")       method = find_business;
    if (ktype == "UDDI_QUERY_FSERVICE")        method = find_service;
    if (ktype == "UDDI_QUERY_GSERVICE_DETAIL") method = get_servicedetail;

    xml = string(envelope_header, method, close_envelope);
    len = strlen(xml);

    finished_message =  string("POST ", path,  " HTTP/1.0\r\n");
    finished_message =  string(finished_message, "Accept: text/xml\r\n");
    finished_message =  string(finished_message, "Accept: multipart/*\r\n");
    finished_message =  string(finished_message, "Host: ", get_host_ip(), "\r\n");
    finished_message =  string(finished_message, "User-Agent: NESSUS::SOAP\r\n");
    finished_message =  string(finished_message, "Content-Length: ", len, "\r\n");
    finished_message =  string(finished_message, "Content-Type: text/xml; charset=utf-8\r\n"); 
    finished_message =  string(finished_message, "SOAPAction: ''\r\n\r\n", xml);
    return(finished_message);
}


