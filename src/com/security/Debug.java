package com.security;

public class Debug {
    public static void log(String s){
        System.out.println(s);
    }
    public static void logException(Throwable e){
        e.printStackTrace();
    }
}
