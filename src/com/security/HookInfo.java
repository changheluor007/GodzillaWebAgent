package com.security;

import java.util.ArrayList;

public class HookInfo
{
    private String className;
    private String methodName;
    private int requestParameterId;
    private int responseParameterId;
    private String[] methodParameters;

    public HookInfo(String className, String methodName, int requestParameterId, int responseParameterId, String[] methodParameters) {
        this.className = className;
        this.methodName = methodName;
        this.requestParameterId = requestParameterId;
        this.responseParameterId = responseParameterId;
        this.methodParameters = methodParameters;
    }

    public String getClassName() {
        return className;
    }

    public void setClassName(String className) {
        this.className = className;
    }

    public String getMethodName() {
        return methodName;
    }

    public void setMethodName(String methodName) {
        this.methodName = methodName;
    }

    public int getRequestParameterId() {
        return requestParameterId;
    }

    public void setRequestParameterId(int requestParameterId) {
        this.requestParameterId = requestParameterId;
    }

    public int getResponseParameterId() {
        return responseParameterId;
    }

    public void setResponseParameterId(int responseParameterId) {
        this.responseParameterId = responseParameterId;
    }

    public String[] getMethodParameters() {
        return methodParameters;
    }

    public void setMethodParameters(String[] methodParameters) {
        this.methodParameters = methodParameters;
    }
}
