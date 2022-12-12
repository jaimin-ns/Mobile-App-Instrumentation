## Resources

https://www.youtube.com/watch?v=0QIJRjdnT2I

## Introduction

### 1. Frida

- It lets you inject snippets of JavaScript or your own library into native apps on Windows, macOS, GNU/Linux, iOS, Android, and QNX.

- Frida also provides you with some simple tools built on top of the Frida API. These can be used as-is, tweaked to your needs, or serve as examples of how to use the API.


## Frida script/command injection

- 

## Get android architecture

adb shell getprop ro.product.cup.abi
adb shell getprop ro.product.cup.abilist


## Understanding the Frida CLI

- 

## Hello world script

Java.perform();

- Annonymas function

Java.perform(() => {

});

Java.perform(function(){

});

frida -U -f com.example.helloapp -l helloscript.js

## Frida script to load classes

- List classes of hello world app
- Java.enumerateLoadedClasses

- how to rerun the scripts ctrl + s & enter


frida -U -f com.example.helloapp -l listclasses.js
frida -U -f hpandro.android.security -l listclasses.js

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

const rootcheckclass = Java.use("sg.vantagepoint.a.c");

rootcheckclass.a.implementation = function(){
	
}

## Dumping function parameters

frida -U -f owasp.mstg.uncrackable1 -l crackme1-rootbypass.js
frida -U -n "Uncrackable1" -l dump-function-parameters.js

- changed return true for method a of class a
- And dumped function parameters

## Re-using app functions in Frida scripts and decrypting passwords

- Create sleleton of the target function in JS

- $new
	- Instantiate objects by calling $new()
	- 

