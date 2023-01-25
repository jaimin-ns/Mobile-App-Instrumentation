## Workshop: Frida instrumentation for android

Welcome to the Frida instrumentation workshop for Android! In this workshop, you will learn how to use Frida, a powerful dynamic instrumentation tool, to manipulate the behavior of Android apps at runtime.

### Authors
- [Jaimin Gohel](https://twitter.com/jaimin_gohel)
- [Viral Bhatt](https://twitter.com/viralbhatt100)

- Presented at: [NSConclave2023](https://nsconclave.net-square.com)

### What is Dynamic binary instrumentation?

- Dynamic binary instrumentation (DBI) can be thought of as a technique used by a spy organization to gather information about the inner workings of another organization.

Imagine that there is a secret spy organization that wants to learn more about the operations of a rival organization. One way they could do this is by sending in a spy to gather information from inside the rival organization. This spy could observe meetings, read documents, and gather other types of information about the rival organization's activities.

Now imagine that the rival organization has a number of different programs that it uses to run its operations. These programs might be used to manage finances, communicate with employees, or perform other tasks. The spy organization could use dynamic binary instrumentation to analyze and modify these programs while they are running in order to gather more information about the rival organization's activities.

In this analogy, the rival organization is like a compiled program, and the spy organization is like a DBI tool. Just as the spy gathers information by observing and interacting with the rival organization, the DBI tool gathers information by analyzing and modifying the compiled program.

Before you get started, you will need to make sure you have the following prerequisites:

- A computer running macOS, Linux, or Windows
- A device running Android 7.0 or newer, or an emulator running Android 7.0 or newer
- The Frida Python package installed on your computer (pip install frida)
- ADB (Android Debug Bridge) installed and configured on your computer
- JadX-GUI

Once you have everything set up, you're ready to get started! Here is a brief outline of what we will cover in this workshop:

1. Introduction to Frida and dynamic instrumentation
2. Setting up a Frida server on your Android device
3. Injecting Frida into an Android app
4. Manipulating the behavior of an Android app using Frida
5. Advanced techniques for Android instrumentation with Frida


Let's get started!

### Introduction to Frida and dynamic instrumentation

Frida is a dynamic instrumentation tool that allows you to manipulate the behavior of running processes on a device. It works by injecting a JavaScript library into the process, which gives you access to the process's memory and allows you to manipulate its behavior in real-time.

Dynamic instrumentation is a powerful technique that can be used for a wide range of purposes, such as reverse engineering, penetration testing, and automating tasks. In this workshop, we will focus on using Frida for reverse engineering Android apps.

### Setting up a Frida server on your Android device

Before you can use Frida to instrument an Android app, you will need to set up a Frida server on your Android device. The Frida server is a small daemon that runs on your device and allows Frida to communicate with it.

- Get CPU architecture of your device/emulator

- `adb shell getprop ro.product.cup.abi`
- `adb shell getprop ro.product.cup.abilist`

To set up the Frida server on your device, follow these steps:

1. Download the Frida server based on your device architecture from the Frida github releases https://github.com/frida/frida/releases
2. Transfer the binary to your Android device using ADB (adb push frida-server /data/local/tmp/)
3. Connect to your device using ADB (adb shell)
4. Once the Frida server is transffered, you can start it by running the following command:

`/data/local/tmp/frida-server &`

The Frida server should now be running on your device and ready for use.

Next step is to setup frida on the system,run following to install frida on the system.

`pip3 install frida-tools`

### Interacting with android app using Frida

Now that the Frida server is set up on your device, you can use Frida to instrument an Android app. 

To interact with android app using Frida, follow these steps:

1. Make sure the Frida server is running on your device
2. Find the package name of the app you want to instrument (e.g. com.example.app)
3. Run the following command to list the processes running on your device: `frida-ps -U`
4. Find the package name of the app you want to instrument in the list of processes.
5. Run the following command to inject Frida into the app's process: `frida -U -f com.example.app -l script.js`

Where com.example.app is the package name of the app, and script.js is the name of the JavaScript script that will be injected into the app's process.

The Frida library should now be injected into the app's process, and you should see a message in the terminal indicating that Frida is running.

#### Multiple ways to attach to runnine processes

#### 1. Interactive

1. Run `frida -U -f <Package name>`
2. This creates an interactive shell
3. Write your scripts inside this shell

#### 2. Attach script

1. Write the frida script inside the .js file
2. Pass it as an argument using -l option
3. Run `frida -U -f <Package name> -l <agent.js>`
4. The frida script will be excuted prallaly with target application execution

#### 3. Python script

- Using Python and JS allows for quick development with a risk-free API. Frida can help you easily catch errors in JS and provide you an exception rather than crashing.

1. Create a python file to spawn the target process
2. Write an agent in JS for the hooking logic
3. Use JS inside your python file to interact with process

### Manipulating the behavior of an Android app using Frida

Now that Frida is injected into the app's process, you can use it to manipulate the app's behavior. Frida provides a powerful JavaScript API that allows you to enumerate the app's classes, methods, and fields, and to manipulate their behavior at runtime.

Here is a simple example of how you can use Frida to change the behavior of an Android app:

```javascript
Java.perform(function() {
  // Find the class we want to manipulate
  var targetClass = Java.use("com.example.app.TargetClass");

  // Replace the implementation of the target method with our own
  targetClass.targetMethod.implementation = function(arg1, arg2) {
    console.log("targetMethod called with args: " + arg1 + ", " + arg2);

    // Call the original implementation of the method
    var result = this.targetMethod(arg1, arg2);

    // Return the result of the original method
    return result;
  };
});
```

In this example, we are using Frida to find the `TargetClass` class in the app, and to replace the implementation of the `targetMethod` method with our own code. Our code logs the arguments passed to the method, calls the original implementation of the method, and returns the result.

Using Frida in this way allows you to modify the behavior of the app in real-time, without having to modify the app's code or rebuild it.

### Advanced techniques for Android instrumentation with Frida

Frida provides many advanced features that allow you to perform more sophisticated manipulations of Android apps. Here are a few examples of what you can do with Frida:

- Hook into method calls made by the app, and manipulate the arguments or return values
- Bypassing client side encryption
- Client side checks such as ROOT detection, SSL pinning, Emulator detection, Biomatric Authentication

I hope this section has given you a good introduction to Frida and dynamic instrumentation on Android. With Frida, you can unlock the full potential of Android apps and use them in ways that were never intended by their developers. Let's dive into more details, Happy hacking! 


## Understanding the Frida CLI

- Here is an example of how to use the Frida CLI to list the process names and IDs on a device:

- Download: [com.hpandro.androidsecurity_1.3.apk](https://github.com/RavikumarRamesh/hpAndro1337/tree/main/Android%20AppSec%20(Kotlin)/1.3)

```
# frida-ps -Uai

PID  Name                      Identifier                             
  ------------------------  ---------------------------------------
10780  Android Security Testing  hpandro.android.security               
11856  Camera                    com.motorola.ts.camera                 
12231  Chrome                    com.android.chrome                     
 6148  Exchanges                 com.exchanges                          
 5926  Google                    com.google.android.googlequicksearchbox
24359  Google Play Store         com.android.vending                    
26998  Motorola Notifications    com.motorola.ccc.notification          
11402  Photos                    com.google.android.apps.photos         
11696  YouTube                   com.google.android.youtube   
```

- If you have multiple devices connected you should run following

```
# frida-ls-devices  

Id          Type    Name                OS                   
----------  ------  ------------------  ---------------------
local       local   ns                  Kali GNU/Linux 2022.4
ZF6223RG45  usb     motorola one power  Android 10           
socket      remote  Local Socket 
```

- With -D option you can specify which device you want to interect with

```
# frida-ps -D ZF6223RG45

  PID  Name
-----  -------------------------------------------------------------------------------------------------
30004  .dataservices                                                                                    
30020  .qtidataservices                                                                                 
 1508  ATFWD-daemon                                                                                     
10780  Android Security Testing                                                                         
11856  Camera                                                                                           
 6148  Exchanges                                                                                        
 5926  Google                                                                                           
24359  Google Play Store                                                                                
13047  Moto Audio                                                                                       
26998  Motorola Notifications
```

- Few more important flags are listed below

```
-f TARGET, --file TARGET
                        spawn FILE
-F, --attach-frontmost
		attach to frontmost application
-n NAME, --attach-name NAME
		attach to NAME
-N IDENTIFIER, --attach-identifier IDENTIFIER
		attach to IDENTIFIER
-p PID, --attach-pid PID
		attach to PID
```

## Hello world script

- Let's create a Hello world script to understand the basics.

```javascript
// helloscript.js

Java.perform(()=>{
    console.log("hello world, bye");
});
```
- Inside the block of code passed to Java.perform(), you can use the Frida JavaScript API to interact with the Android runtime and perform various tasks, such as enumerating loaded classes, hooking method calls, and modifying field values.

- Java.perform() is use to hook into the JVM
  - We have access to methods and classes in the memory

```
# frida -U -f hpandro.android.security -l helloscript.js

     ____
    / _  |   Frida 16.0.7 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to motorola one power (id=ZF6223RG45)
Spawned `hpandro.android.security`. Resuming main thread!               
[motorola one power::hpandro.android.security ]-> hello world, bye
```

## Steps of instrumentation with frida

1. Enumerate loaded classes with frida
2. List methods and properties of a class
3. Hook the target function
4. Dumping function parameters
5. Playing around with instances & Modifying the parameter values
6. Modifying the function behaviour


## Enumerate loaded classes with frida

- List classes of target application

```
Java.enumerateLoadedClasses(callbacks): enumerate classes loaded right now, where callbacks is an object specifying:

onMatch(name, handle): called for each loaded class with name that may be passed to use() to get a JavaScript wrapper.

onComplete(): called when all classes have been enumerated
```

```javascript
// frida -U -f hpandro.android.security -l listclasses.js

Java.perform(()=>{
    Java.enumerateLoadedClasses({
        onMatch : function(name, handle){
            if(name.includes("AES")){
                console.log(name);
            }
            
        },
        onComplete : function(){
            console.log("--- done ---");
        }
    });
});
```

`frida -U -f com.example.helloapp -l listclasses.js`
`frida -U -f hpandro.android.security -l listclasses.js`

hpandro.android.security.ui.activity.task.encryption.AESActivity

## List methods and properties of a class

### Method - 1

- `Java.use()`
  - `Java.use(className):` dynamically get a JavaScript wrapper for className that you can instantiate objects from by calling `$new()` on it to invoke a constructor.
	- Mention the class name inside `Java.use()`
	- We can use CONST or var to store `Java.use()`

```javascript
// frida -U -f hpandro.android.security -l list-methods-and-properties.js

Java.perform(()=>{
    console.log("--- ok ---");
    const activityclass = Java.use("hpandro.android.security.ui.activity.task.encryption.AESActivity");
    console.log(activityclass);
    console.log(Object.getOwnPropertyNames(activityclass).join("\n\t"));
});
```
`frida -U -f hpandro.android.security -l list-methods-and-properties.js`

### Method - 2

`Java.enumerateMethods(query):` enumerate methods matching query, specified as `"class!method"`.

```javascript
// frida -U -f hpandro.android.security -l list-methods-and-properties-1.js

Java.perform(() => {
  const groups = Java.enumerateMethods('*AES*!*decrypt*')
  console.log(JSON.stringify(groups, null, 2));
});
```

## Hook the target function

- Decompile APK using Jadx and identify target function to hook

- Write coresponding frida script

- check if function is called

- [Download APK](https://github.com/OWASP/owasp-mastg/tree/master/Crackmes/Android/Level_01)

```javascript
// frida -U -f owasp.mstg.uncrackable1 -l func-call.js

Java.perform(()=>{
  const rootcheckclass = Java.use("sg.vantagepoint.a.c");

  rootcheckclass.a.implementation = function(){
    console.log("a() function called!");
    return true;
  }
});
```

- modify the function's return values

```javascript
// frida -U -f owasp.mstg.uncrackable1 -l func-call.js

Java.perform(()=>{
  const rootcheckclass = Java.use("sg.vantagepoint.a.c");

  rootcheckclass.a.implementation = function(){
    console.log("a() function called!");
    return false;
  }
});
```

```javascript
// frida -U -f owasp.mstg.uncrackable1 -l crackme1-rootbypass.js

Java.perform(()=>{
    const rootcheckclass = Java.use("sg.vantagepoint.a.c");

    rootcheckclass.a.implementation = function(){
        console.log("--bypass c.a()--");
        return false;
    }

    rootcheckclass.b.implementation = function(){
        console.log("--bypass c.b()--");
        return false;
    }

    rootcheckclass.c.implementation = function(){
        console.log("--bypass c.c()--");
        return false;
    }
});
```

`frida -U -f owasp.mstg.uncrackable1 -l crackme1-rootbypass.js`

## Dumping function parameters

`frida -U -f owasp.mstg.uncrackable1 -l dump-function-parameters.js`

```javascript
// frida -U -n "Uncrackable1" -l dump-function-parameters.js

Java.perform(()=>{

    const classa = Java.use("sg.vantagepoint.uncrackable1.a");

    classa.a.overload("java.lang.String").implementation = function(s){
        console.log(s.toString());

        return true;
    }
});

```

- changed return true for method a of class a
- And dumped function parameters

## Playing around with instances & Modifying the parameter values

- We need to work with existing instance sometimes
  - Scan application memory to find the instances
  - `Java.choose(className, callbacks):` enumerate live instances of the `className` class by scanning the Java heap, where callbacks is an object specifying:

  - `onMatch(instance):` called with each live instance found with a ready-to-use instance.

  - `onComplete():` called when all instances have been enumerated

```javascript
Java.perform(function() {

    // We are scanning the application memory for existing instances of the Class.
    Java.choose('com.example.classname', {
        // onMatch - Callback => If an instance has been found,
        onMatch: function(instance) {
            // code if an instance has been found
            send("An instance of the class has been found = " + instance)

            // Do operations on the found instance
        },
        // onComplete - Callback => Finished scanning the app memory regarding to the instance.
        onComplete: function() {
            send("Frida has finished scanning the application memory for class instances")
        }

    })
})
```

### CTF Challenges

- dice game
- fridaFunc
- clickMe

## Use Cases

### Spoof geo location

- Spoof geo location of android google maps

```javascript
// frida -U -f com.google.android.apps.maps

Java.perform(() => {
  var Location = Java.use('android.location.Location');
  Location.getLatitude.implementation = function() {
    return 26.4679656;
  }
  Location.getLongitude.implementation = function() {
    return 74.6343847;
  }
})
```

### Re-using app functions in Frida scripts and decrypting passwords

- `$new`
  - Instantiate objects by calling $new()

- [Download APK](https://github.com/OWASP/owasp-mastg/tree/master/Crackmes/Android/Level_01)

```javascript
// frida -U -f owasp.mstg.uncrackable1 -l decrypt-and-show.js

Java.perform(()=>{
  // base64 decode

  const base64 = Java.use("android.util.Base64");
  var arrayofbytes = base64.decode("5UJiFctbmgbDoLXmpL12mkno8HT4Lv8dlat8FxR2GOc=",0);

  // b function
  const bfunclass = Java.use("sg.vantagepoint.uncrackable1.a");
  var encKey = bfunclass.b("8d127684cbc37c17616d806cf50473cc");

  // a function
  const afunclass = Java.use("sg.vantagepoint.a.a");
  var decryptedarray = afunclass.a(encKey, arrayofbytes);

  // convert to string and show
  const strclass = Java.use("java.lang.String");
  var decryptedpass = strclass.$new(decryptedarray);
  console.log(decryptedpass);
});
```

`frida -U -f owasp.mstg.uncrackable1 -l decrypt-and-show.js`

### AES Encryption bypass

- Here we have task to identify the encryption logic and try to decrypt the string presented at the start of activity.

- Download: [com.hpandro.androidsecurity_1.3.apk](https://github.com/RavikumarRamesh/hpAndro1337/tree/main/Android%20AppSec%20(Kotlin)/1.3)

```javascript
// frida -U -f hpandro.android.security -l "hp andro/aes-decrypt.js"

Java.perform(function x() {
    var ScopeObject = Java.use("hpandro.android.security.ui.activity.task.encryption.AESActivity");
    var scopeInstance = ScopeObject.$new();

    console.log(scopeInstance.decryptStrAndFromBase64('dfdfdf','hpAndro','UhIF1tR4HCQOdf1SXQXVOIeT7L4yd76Yh0K7ULfGJCkOcjB7OrAciDuA0/HlpfeR'));
})
```

- Perform above task with `Java.choose()`
- Perform DES task in hpAndro

### RSA Encryption bypass

- Here we have task to identify the encryption logic and try to decrypt the string presented at the start of activity.

- Download: [com.hpandro.androidsecurity_1.3.apk](https://github.com/RavikumarRamesh/hpAndro1337/tree/main/Android%20AppSec%20(Kotlin)/1.3)


```javascript
// frida -U -f hpandro.android.security -l "/hp andro/rsa-decrypt.js"

Java.perform(function () {
    let RSAActivity = Java.use("hpandro.android.security.ui.activity.task.encryption.RSAActivity");
    RSAActivity["decrypt"].implementation = function (privateKey, bArr) {
        console.log('decrypt is called' + ', ' + 'privateKey: ' + privateKey + ', ' + 'bArr: ' + bArr);
        let ret = this.decrypt(privateKey, bArr);

        const strclass = Java.use("java.lang.String");
        var decryptedpass = strclass.$new(ret);
        console.log('decrypt ret value is ' + decryptedpass);
        return ret;
    };
});
```

### Enable remote debugging of Android WebViews at Runtime

- Often we deal with cross platform apps in our pentests. This tricks comes in really handy to debug the application logic.

```javascript
Java.perform(function() {
        Java.choose("android.webkit.WebView", {
            "onMatch": function(o) {
                try {
                    // Use a Runnable to invoke the setWebContentsDebuggingEnabled
                    // method in the same thread as the WebView
                    var Runnable = Java.use('java.lang.Runnable');
                    var MyRunnable = Java.registerClass({
                        name: 'com.example.MyRunnable',
                        implements: [Runnable],
                        methods: {
                            'run': function() {
                                o.setWebContentsDebuggingEnabled(true);
                                console.log('WebView Debugging should be enabled');
                            }
                        }
                    });
                    var runnable = MyRunnable.$new();
                    o.post(runnable);
                } catch (e) {
                    console.log("Execution failed " + e.message);
                }
            },
            "onComplete": function() {
                console.log("Execution completed")
            }
        })
    }
);
```

### Hacking a vulnerable bank application

- Setup the Damn Vulnerable Bank 
  - https://github.com/rewanthtammana/Damn-Vulnerable-Bank

Username | Password | Account Number | Beneficiaries | Admin privileges
--- | --- | --- | --- | ---
user1 | password1 | 111111 | 222222, 333333, 444444 | No
user2 | password2 | 222222 | None | No
user3 | password3 | 333333 | None | No
user4 | password4 | 444444 | None | No
admin | admin | 999999 | None | Yes

- Bypass basic frida detection
- Start the frida server on different port
  - `./frida -l 0.0.0.0:1337`

- Connect to frida using `-H` flag
  - `frida -H 192.168.56.101:1337 -f com.app.damnvulnerablebank`

- Bypass root detection using frida

- Dump the encrypted and plain-text response
- Get `accesstoken` from shared preference
  - https://codeshare.frida.re/@ninjadiary/frinja---sharedpreferences/

- bypass fingerprint check while Sending money
  - https://github.com/WithSecureLabs/android-keystore-audit/blob/master/frida-scripts/fingerprint-bypass.js

- Get data from clipboard

- Log everything!

## Resources & Credits

- https://frida.re/docs/home/
- https://github.com/RavikumarRamesh/hpAndro1337
- https://github.com/rewanthtammana/Damn-Vulnerable-Bank
- https://github.com/OWASP/owasp-mastg/tree/master/Crackmes/Android
- https://github.com/WithSecureLabs/android-keystore-audit/blob/master/frida-scripts
- https://github.com/apkunpacker/FridaScripts/
- https://www.youtube.com/watch?v=JK8Azi7f13E
- https://www.youtube.com/watch?v=0QIJRjdnT2I
