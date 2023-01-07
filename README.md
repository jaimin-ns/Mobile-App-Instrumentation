## Frida instrumentation for android

Welcome to the Frida instrumentation workshop for Android! In this workshop, you will learn how to use Frida, a powerful dynamic instrumentation tool, to manipulate the behavior of Android apps at runtime.

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

Next step is to setup frida on the system,run followin to install frida on the system.

`pip3 install frida-tools`

### Installing Vulnerable apps

- INSERT DRIVE LINK

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

1. 

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

```
// helloscript.js

Java.perform(()=>{
    console.log("hello world, bye");
});
```

`frida -U -f hpandro.android.security -l helloscript.js`



`Java.perform();`

- Annonymas function

```
Java.perform(() => {

});

Java.perform(function(){

});
```

## Frida script to load classes

- List classes of hello world app
- Java.enumerateLoadedClasses

- how to rerun the scripts ctrl + s & enter


`frida -U -f com.example.helloapp -l listclasses.js`
`frida -U -f hpandro.android.security -l listclasses.js`

hpandro.android.security.ui.activity.task.encryption.AESActivity

## List methods and properties

- Java.use()
	- Create a a wrapper of class
	- mention the class name

	- can use CONST or var
- 

## Hook functions

- How to use frida to hook functions(methods)
- modify the function's return values

```
const rootcheckclass = Java.use("sg.vantagepoint.a.c");

rootcheckclass.a.implementation = function(){
	
}
```

## Dumping function parameters

`frida -U -f owasp.mstg.uncrackable1 -l crackme1-rootbypass.js`
`frida -U -n "Uncrackable1" -l dump-function-parameters.js`

- changed return true for method a of class a
- And dumped function parameters

## Re-using app functions in Frida scripts and decrypting passwords

- Create sleleton of the target function in JS

- $new
	- Instantiate objects by calling $new()
	- 

## Resources

https://www.youtube.com/watch?v=0QIJRjdnT2I
