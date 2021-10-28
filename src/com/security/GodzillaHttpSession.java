package com.security;

import javax.servlet.http.HttpSession;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.UUID;

public class GodzillaHttpSession implements HttpSession {
    private final long creationTime;
    private final String uuid;
    private long lastAccessedTime;
    private final HashMap contentMap;

    public GodzillaHttpSession(String sessionId){
        this.creationTime=System.currentTimeMillis();
        this.lastAccessedTime=System.currentTimeMillis();
        this.uuid= sessionId;
        this.contentMap=new HashMap();
        refreshTime();
    }
    @Override
    public long getCreationTime() {
        return this.creationTime;
    }

    @Override
    public String getId() {
        return this.uuid;
    }

    @Override
    public long getLastAccessedTime() {
        return this.lastAccessedTime;
    }

    @Override
    public ServletContext getServletContext() {
        return null;
    }

    @Override
    public void setMaxInactiveInterval(int i) {

    }

    @Override
    public int getMaxInactiveInterval() {
        return 0;
    }

    @Override
    public HttpSessionContext getSessionContext() {
        return null;
    }

    @Override
    public Object getAttribute(String s) {
        return this.contentMap.get(s);
    }

    @Override
    public Object getValue(String s) {
        return this.contentMap.get(s);
    }

    @Override
    public Enumeration getAttributeNames() {
        return null;
    }

    @Override
    public String[] getValueNames() {
        refreshTime();
        Object[] obs= this.contentMap.keySet().toArray();
        String[] retArr=new String[obs.length];
        for (int i=0;i<obs.length;i++){
            retArr[i]=obs[i].toString();
        }
        return retArr;
    }

    @Override
    public void setAttribute(String s, Object o) {
        refreshTime();
        this.contentMap.put(s, o);
    }

    @Override
    public void putValue( String key, Object val){
        refreshTime();
        this.contentMap.put(key, val);
    }

    @Override
    public void removeAttribute(String s) {
        refreshTime();
        this.contentMap.remove(s);
    }

    @Override
    public void removeValue(String s) {
        refreshTime();
        this.contentMap.remove(s);
    }

    @Override
    public void invalidate() {
        this.lastAccessedTime=0;
        this.contentMap.clear();
    }

    public void refreshTime(){
        if (lastAccessedTime!=0){
            this.lastAccessedTime=System.currentTimeMillis();
        }
    }

    @Override
    public boolean isNew() {
        refreshTime();
        return false;
    }
}
