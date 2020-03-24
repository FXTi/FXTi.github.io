import frida, sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

jscode = """
var fIntercepted = false;

function revealNativeMethods() {
    if (fIntercepted === true) {
        return;
    }
    var jclassAddress2NameMap = {};
    var androidRunTimeSharedLibrary = "libart.so"; // may change between devices
    Module.enumerateSymbolsSync(androidRunTimeSharedLibrary).forEach(function(symbol){
        switch (symbol.name) {
            case "_ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi":
                /*
                    $ c++filt "_ZN3art3JNI21RegisterNativeMethodsEP7_JNIEnvP7_jclassPK15JNINativeMethodib"
                    art::JNI::RegisterNativeMethods(_JNIEnv*, _jclass*, JNINativeMethod const*, int, bool)
                */
                var RegisterNativeMethodsPtr = symbol.address;
                console.log("RegisterNativeMethods is at " + RegisterNativeMethodsPtr);
                Interceptor.attach(RegisterNativeMethodsPtr, {
                    onEnter: function(args) {
                        var methodsPtr = ptr(args[2]);
                        var methodCount = parseInt(args[3]);
                        for (var i = 0; i < methodCount; i++) {
                            var pSize = Process.pointerSize;
                            /*
                                https://android.googlesource.com/platform/libnativehelper/+/master/include_jni/jni.h#129
                                typedef struct {
                                    const char* name;
                                    const char* signature;
                                    void* fnPtr;
                                } JNINativeMethod;
                            */
                            var structSize = pSize * 3; // JNINativeMethod contains 3 pointers
                            var namePtr = Memory.readPointer(methodsPtr.add(i * structSize));
                            var sigPtr = Memory.readPointer(methodsPtr.add(i * structSize + pSize));
                            var fnPtrPtr = Memory.readPointer(methodsPtr.add(i * structSize + (pSize * 2)));
                            // output schema: className#methodName(arguments)returnVal@address
                            console.log(
                                // package & class, replacing forward slash with dot for convenience
                                jclassAddress2NameMap[args[0]].replace(/\//g, '.') +
                                '#' + Memory.readCString(namePtr) + // method
                                Memory.readCString(sigPtr) + // signature (arguments & return type)
                                '@' + fnPtrPtr // C side address
                            );
                            console.log(hexdump(fnPtrPtr, {
                                offset: 0,
                                length: 128,
                                header: false,
                                ansi: false,
                            }));
                        }
                    },
                    onLeave: function (ignoredReturnValue) {}
                });
                break;
            case "_ZN3art3JNI9FindClassEP7_JNIEnvPKc": // art::JNI::FindClass
                Interceptor.attach(symbol.address, {
                    onEnter: function(args) {
                        if (args[1] != null) {
                            jclassAddress2NameMap[args[0]] = Memory.readCString(args[1]);
                        }
                    },
                    onLeave: function (ignoredReturnValue) {}
                });
                break;
        }
    });
    fIntercepted = true;
}

Java.perform(revealNativeMethods);
"""

'''
process = frida.get_usb_device().attach('com.zhuotong.crackme')
script = process.create_script(jscode)
script.on('message', on_message)
print('[*] Running CTF')
script.load()
sys.stdin.read()
'''
device = frida.get_usb_device()
pid = device.spawn(["com.zhuotong.crackme"])
session = device.attach(pid)
script = session.create_script(jscode)
script.on('message', on_message)
print('[*] Running CTF')
script.load()
device.resume(pid)
sys.stdin.read()
