Android key blob decryptor
==========================

This tool decrypts Android keystore key and certificate blobs, given 
the ```.masterkey``` file and the device's PIN or password. Key blobs that 
are protected by a hardware-backed key cannot be decrypted. 

The tool supports Android M keymaster v1.0 blobs, encrypted with the 
default (all zero) key. Blobs from later versions may not be supported.

Usage:

Build using the provided Gradle script. Then invoke as follows:

```$ java -jar ksdecryptor-all.jar <master key file>  <key file>  <password>```

See this blog post for more details about the tool and Android keystore 
implementation:

http://nelenkov.blogspot.com/2015/06/keystore-redesign-in-android-m.html

