package com.security;


import javax.servlet.http.HttpSession;
import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.security.SecureRandom;
import java.util.*;

public class GodzillaSessionManage implements Runnable {
    private static final HashMap<String, GodzillaHttpSession> godzillaHttpSessionHashMap=new HashMap();
    private static final StandardSessionIdGenerator sessionIdGenerator=new StandardSessionIdGenerator();
    private static final long sleepTime=1000*60*3;
    public static final String SessionName="CSESSIONID";

    static {
        new Thread(new GodzillaSessionManage()).start();
    }

    public GodzillaSessionManage(){

    }

    public static GodzillaHttpSession getSession(String sessionId){
        GodzillaHttpSession godzillaSession;
        if (sessionId==null){
            godzillaSession=new GodzillaHttpSession(sessionIdGenerator.generateSessionId(null));
            sessionId=godzillaSession.getId();
            godzillaHttpSessionHashMap.put(sessionId, godzillaSession);
            godzillaSession.refreshTime();
        }else {
            godzillaSession=godzillaHttpSessionHashMap.get(sessionId);
            if (godzillaSession==null){
                godzillaSession=getSession(null);
            }
            godzillaSession.refreshTime();
        }
        return godzillaSession;
    }
    public static GodzillaHttpSession removeSession(HttpSession session){
        return godzillaHttpSessionHashMap.remove(session.getId());
    }
    @Override
    public void run() {
        while (true){
            List<String> removeKeys = new ArrayList<String>();
            try {
                Thread.sleep(sleepTime);
                String[] keys= godzillaHttpSessionHashMap.keySet().toArray(new String[0]);
                for (int i = 0; i < keys.length; i++) {
                    godzillaHttpSessionHashMap.remove(keys[i]);
                }
            }catch (InterruptedException e){
                return;
            }
        }
    }
}
