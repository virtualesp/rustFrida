(function() {
    "use strict";

    var _api = Jni;
    var _className = _api._className;
    var _threadEnv = _api._threadEnv;
    var _POINTER_SIZE = 8;
    var _JNI_INDEX = Object.freeze({
        DefineClass: 5,
        FindClass: 6,
        FromReflectedMethod: 7,
        FromReflectedField: 8,
        ToReflectedMethod: 9,
        GetSuperclass: 10,
        IsAssignableFrom: 11,
        ToReflectedField: 12,
        Throw: 13,
        ThrowNew: 14,
        ExceptionOccurred: 15,
        ExceptionDescribe: 16,
        ExceptionClear: 17,
        FatalError: 18,
        PushLocalFrame: 19,
        PopLocalFrame: 20,
        NewGlobalRef: 21,
        DeleteGlobalRef: 22,
        DeleteLocalRef: 23,
        IsSameObject: 24,
        NewLocalRef: 25,
        EnsureLocalCapacity: 26,
        AllocObject: 27,
        NewObjectA: 30,
        GetObjectClass: 31,
        IsInstanceOf: 32,
        GetMethodID: 33,
        CallObjectMethodA: 36,
        CallBooleanMethodA: 39,
        CallByteMethodA: 42,
        CallCharMethodA: 45,
        CallShortMethodA: 48,
        CallIntMethodA: 51,
        CallLongMethodA: 54,
        CallFloatMethodA: 57,
        CallDoubleMethodA: 60,
        CallVoidMethodA: 63,
        CallNonvirtualObjectMethodA: 66,
        CallNonvirtualBooleanMethodA: 69,
        CallNonvirtualIntMethodA: 81,
        CallNonvirtualLongMethodA: 84,
        CallNonvirtualFloatMethodA: 87,
        CallNonvirtualDoubleMethodA: 90,
        CallNonvirtualVoidMethodA: 93,
        GetFieldID: 94,
        GetObjectField: 95,
        GetBooleanField: 96,
        GetByteField: 97,
        GetCharField: 98,
        GetShortField: 99,
        GetIntField: 100,
        GetLongField: 101,
        GetFloatField: 102,
        GetDoubleField: 103,
        GetStaticMethodID: 113,
        CallStaticObjectMethodA: 116,
        CallStaticBooleanMethodA: 119,
        CallStaticByteMethodA: 122,
        CallStaticCharMethodA: 125,
        CallStaticShortMethodA: 128,
        CallStaticIntMethodA: 131,
        CallStaticLongMethodA: 134,
        CallStaticFloatMethodA: 137,
        CallStaticDoubleMethodA: 140,
        CallStaticVoidMethodA: 143,
        GetStaticFieldID: 144,
        GetStaticObjectField: 145,
        GetStaticBooleanField: 146,
        GetStaticByteField: 147,
        GetStaticCharField: 148,
        GetStaticShortField: 149,
        GetStaticIntField: 150,
        GetStaticLongField: 151,
        GetStaticFloatField: 152,
        GetStaticDoubleField: 153,
        NewStringUTF: 167,
        GetStringUTFChars: 169,
        ReleaseStringUTFChars: 170,
        GetArrayLength: 171,
        NewObjectArray: 172,
        GetObjectArrayElement: 173,
        SetObjectArrayElement: 174,
        RegisterNatives: 215,
        UnregisterNatives: 216,
        MonitorEnter: 217,
        MonitorExit: 218,
        GetJavaVM: 219,
        ExceptionCheck: 228,
        NewDirectByteBuffer: 229,
        GetDirectBufferAddress: 230,
        GetDirectBufferCapacity: 231,
        GetObjectRefType: 232
    });
    var _JNI_NAMES = Object.keys(_JNI_INDEX);

    delete _api._className;
    delete _api._threadEnv;

    function _toPtr(value) {
        return ptr(value);
    }

    function _getCurrentThreadEnv() {
        var env = _toPtr(_threadEnv());
        if (env.toString() === "0x0") {
            throw new Error("Unable to resolve current thread JNIEnv*");
        }
        return env;
    }

    function _getEnvPtr(env) {
        var envPtr = _toPtr(env);
        if (envPtr.toString() === "0x0") {
            throw new Error("JNIEnv* is null");
        }
        return envPtr;
    }

    function _getRefPtr(value) {
        if (value !== null
            && typeof value === "object"
            && Object.prototype.hasOwnProperty.call(value, "__jptr")) {
            value = value.__jptr;
        }
        return _toPtr(value);
    }

    function _resolveEnvAndName(envOrName, maybeName) {
        if (arguments.length === 1) {
            return {
                env: _getCurrentThreadEnv(),
                name: envOrName
            };
        }

        return {
            env: _getEnvPtr(envOrName),
            name: maybeName
        };
    }

    function _resolveEnvAndRef(envOrRef, maybeRef) {
        if (arguments.length === 1) {
            return {
                env: _getCurrentThreadEnv(),
                ref: _getRefPtr(envOrRef)
            };
        }

        return {
            env: _getEnvPtr(envOrRef),
            ref: _getRefPtr(maybeRef)
        };
    }

    function _getIndex(name, allowMissing) {
        if (typeof name !== "string") {
            throw new TypeError("JNI function name must be a string");
        }

        if (Object.prototype.hasOwnProperty.call(_JNI_INDEX, name)) {
            return _JNI_INDEX[name];
        }

        if (allowMissing) {
            return null;
        }

        throw new Error("Unknown JNI function: " + name);
    }

    function _getAddressByIndex(env, index) {
        var table = Memory.readPointer(_getEnvPtr(env));
        return Memory.readPointer(table.add(index * _POINTER_SIZE));
    }

    function _makeEntry(env, name, allowMissing) {
        var index = _getIndex(name, allowMissing);
        if (index === null) {
            return null;
        }

        return {
            name: name,
            index: index,
            address: _getAddressByIndex(env, index)
        };
    }

    function _getEntries(env) {
        var envPtr = arguments.length === 0 ? _getCurrentThreadEnv() : _getEnvPtr(env);
        var out = [];

        for (var i = 0; i < _JNI_NAMES.length; i++) {
            out.push(_makeEntry(envPtr, _JNI_NAMES[i], false));
        }

        return out;
    }

    function _getTable(env) {
        var envPtr = arguments.length === 0 ? _getCurrentThreadEnv() : _getEnvPtr(env);
        var table = Object.create(null);

        for (var i = 0; i < _JNI_NAMES.length; i++) {
            var name = _JNI_NAMES[i];
            table[name] = _makeEntry(envPtr, name, false);
        }

        return table;
    }

    function _getAddress(envOrName, maybeName) {
        var resolved = _resolveEnvAndName.apply(null, arguments);
        return _getAddressByIndex(resolved.env, _getIndex(resolved.name, false));
    }

    function _readCStringMaybe(value) {
        var p = _toPtr(value);
        if (p.toString() === "0x0") {
            return null;
        }
        return Memory.readCString(p);
    }

    function _parseJniTypeSequence(seq, start, endChar) {
        var out = [];
        var i = start;

        while (i < seq.length && seq[i] !== endChar) {
            var begin = i;

            while (seq[i] === "[") {
                i++;
            }

            if (i >= seq.length) {
                throw new Error("Invalid JNI signature: " + seq);
            }

            if (seq[i] === "L") {
                i++;
                while (i < seq.length && seq[i] !== ";") {
                    i++;
                }
                if (i >= seq.length) {
                    throw new Error("Invalid JNI signature: " + seq);
                }
                i++;
            } else {
                i++;
            }

            out.push(seq.slice(begin, i));
        }

        return {
            types: out,
            end: i
        };
    }

    function _parseMethodSignature(jniSig) {
        if (typeof jniSig !== "string" || jniSig.charAt(0) !== "(") {
            throw new TypeError("JNI signature must start with '('");
        }

        var params = _parseJniTypeSequence(jniSig, 1, ")");
        if (params.end >= jniSig.length || jniSig[params.end] !== ")") {
            throw new Error("Invalid JNI signature: " + jniSig);
        }

        var ret = _parseJniTypeSequence(jniSig, params.end + 1, "\0");
        if (ret.types.length !== 1) {
            throw new Error("Invalid JNI signature: " + jniSig);
        }

        return {
            params: params.types,
            ret: ret.types[0]
        };
    }

    function _normalizeTypeList(typesOrSig) {
        if (Array.isArray(typesOrSig)) {
            return typesOrSig.slice();
        }

        if (typeof typesOrSig !== "string") {
            throw new TypeError("Expected JNI signature string or type array");
        }

        if (typesOrSig.charAt(0) === "(") {
            return _parseMethodSignature(typesOrSig).params;
        }

        return [typesOrSig];
    }

    function _u32ToI32(value) {
        value = Number(value);
        return value > 0x7fffffff ? value - 0x100000000 : value;
    }

    function _u16ToI16(value) {
        value = Number(value);
        return value > 0x7fff ? value - 0x10000 : value;
    }

    function _u8ToI8(value) {
        value = Number(value);
        return value > 0x7f ? value - 0x100 : value;
    }

    function _bitsToFloat32(bits) {
        var buffer = new ArrayBuffer(4);
        var view = new DataView(buffer);
        view.setUint32(0, Number(bits), true);
        return view.getFloat32(0, true);
    }

    function _bitsToFloat64(bits) {
        var buffer = new ArrayBuffer(8);
        var view = new DataView(buffer);

        if (typeof view.setBigUint64 !== "function") {
            return bits;
        }

        view.setBigUint64(0, BigInt(bits), true);
        return view.getFloat64(0, true);
    }

    function _readJvalue(address, jniType) {
        var base = _toPtr(address);
        var type = typeof jniType === "string" ? jniType : "Ljava/lang/Object;";
        var tag = type.charAt(0);

        switch (tag) {
            case "Z":
                return Memory.readU8(base) !== 0;
            case "B":
                return _u8ToI8(Memory.readU8(base));
            case "C":
                return Number(Memory.readU16(base));
            case "S":
                return _u16ToI16(Memory.readU16(base));
            case "I":
                return _u32ToI32(Memory.readU32(base));
            case "J":
                return BigInt.asIntN(64, BigInt(Memory.readU64(base)));
            case "F":
                return _bitsToFloat32(Memory.readU32(base));
            case "D":
                return _bitsToFloat64(Memory.readU64(base));
            default:
                return Memory.readPointer(base);
        }
    }

    function _readJvalueArray(address, typesOrSig) {
        var base = _toPtr(address);
        var types = _normalizeTypeList(typesOrSig);
        var out = [];

        for (var i = 0; i < types.length; i++) {
            out.push(_readJvalue(base.add(i * 8), types[i]));
        }

        return out;
    }

    function _readJNINativeMethod(address) {
        var base = _toPtr(address);
        var namePtr = Memory.readPointer(base);
        var sigPtr = Memory.readPointer(base.add(_POINTER_SIZE));
        var fnPtr = Memory.readPointer(base.add(_POINTER_SIZE * 2));

        return {
            address: base,
            namePtr: namePtr,
            sigPtr: sigPtr,
            fnPtr: fnPtr,
            name: _readCStringMaybe(namePtr),
            sig: _readCStringMaybe(sigPtr)
        };
    }

    function _readJNINativeMethods(address, count) {
        var base = _toPtr(address);
        var total = Number(count);
        var out = [];

        for (var i = 0; i < total; i++) {
            out.push(_readJNINativeMethod(base.add(i * _POINTER_SIZE * 3)));
        }

        return out;
    }

    function _makeEnvHelper() {
        var getDirectBufferAddressFn = null;
        var getDirectBufferCapacityFn = null;

        function _getDirectBufferAddressFn(env) {
            if (getDirectBufferAddressFn === null) {
                getDirectBufferAddressFn = new NativeFunction(
                    _getAddressByIndex(env, _JNI_INDEX.GetDirectBufferAddress),
                    "pointer",
                    ["pointer", "pointer"]
                );
            }
            return getDirectBufferAddressFn;
        }

        function _getDirectBufferCapacityFn(env) {
            if (getDirectBufferCapacityFn === null) {
                getDirectBufferCapacityFn = new NativeFunction(
                    _getAddressByIndex(env, _JNI_INDEX.GetDirectBufferCapacity),
                    "int64",
                    ["pointer", "pointer"]
                );
            }
            return getDirectBufferCapacityFn;
        }

        return {
            get ptr() {
                return _getCurrentThreadEnv();
            },
            getObjectClass: function(envOrObj, maybeObj) {
                var resolved = _resolveEnvAndRef.apply(null, arguments);
                var raw = _api._getObjectClass(resolved.env, resolved.ref);
                return raw === null || raw === undefined ? null : _toPtr(raw);
            },
            getSuperclass: function(envOrClazz, maybeClazz) {
                var resolved = _resolveEnvAndRef.apply(null, arguments);
                var raw = _api._getSuperclass(resolved.env, resolved.ref);
                // Object / interface 的 superclass 为 null，不是错误
                return raw === null || raw === undefined ? null : _toPtr(raw);
            },
            isSameObject: function(envOrA, aOrB, maybeB) {
                var env = arguments.length >= 3 ? _getEnvPtr(envOrA) : _getCurrentThreadEnv();
                var a = arguments.length >= 3 ? _getRefPtr(aOrB) : _getRefPtr(envOrA);
                var b = arguments.length >= 3 ? _getRefPtr(maybeB) : _getRefPtr(aOrB);
                return !!_api._isSameObject(env, a, b);
            },
            isInstanceOf: function(envOrObj, objOrClazz, maybeClazz) {
                var env = arguments.length >= 3 ? _getEnvPtr(envOrObj) : _getCurrentThreadEnv();
                var obj = arguments.length >= 3 ? _getRefPtr(objOrClazz) : _getRefPtr(envOrObj);
                var clazz = arguments.length >= 3 ? _getRefPtr(maybeClazz) : _getRefPtr(objOrClazz);
                return !!_api._isInstanceOf(env, obj, clazz);
            },
            exceptionCheck: function(env) {
                var e = arguments.length >= 1 ? _getEnvPtr(env) : _getCurrentThreadEnv();
                return !!_api._exceptionCheck(e);
            },
            exceptionOccurred: function(env) {
                var e = arguments.length >= 1 ? _getEnvPtr(env) : _getCurrentThreadEnv();
                var raw = _api._exceptionOccurred(e);
                return raw === null || raw === undefined ? null : _toPtr(raw);
            },
            exceptionClear: function(env) {
                var e = arguments.length >= 1 ? _getEnvPtr(env) : _getCurrentThreadEnv();
                _api._exceptionClear(e);
                return true;
            },
            findClass: function(envOrName, maybeName) {
                // (name) 或 (env, name)
                var resolved = _resolveEnvAndName.apply(null, arguments);
                var raw = _api._findClass(resolved.env, resolved.name);
                return raw === null || raw === undefined ? null : _toPtr(raw);
            },
            newStringUtf: function(envOrStr, maybeStr) {
                var env, s;
                if (arguments.length >= 2) {
                    env = _getEnvPtr(envOrStr);
                    s = String(maybeStr);
                } else {
                    env = _getCurrentThreadEnv();
                    s = String(envOrStr);
                }
                var raw = _api._newStringUtf(env, s);
                return raw === null || raw === undefined ? null : _toPtr(raw);
            },
            newLocalRef: function(envOrObj, maybeObj) {
                var resolved = _resolveEnvAndRef.apply(null, arguments);
                var raw = _api._newLocalRef(resolved.env, resolved.ref);
                return raw === null || raw === undefined ? null : _toPtr(raw);
            },
            deleteLocalRef: function(envOrObj, maybeObj) {
                var resolved = _resolveEnvAndRef.apply(null, arguments);
                _api._deleteLocalRef(resolved.env, resolved.ref);
                return true;
            },
            readJString: function(envOrJstr, maybeJstr) {
                var resolved = _resolveEnvAndRef.apply(null, arguments);
                var env = resolved.env;
                var strPtr = resolved.ref;
                if (strPtr.toString() === "0x0") {
                    return null;
                }
                return _api._readJString(env, strPtr);
            },
            getClassName: function(envOrClazz, maybeClazz) {
                var resolved = _resolveEnvAndRef.apply(null, arguments);
                var cls = resolved.ref;
                if (cls.toString() === "0x0") {
                    return null;
                }
                return _className(resolved.env, cls);
            },
            getObjectClassName: function(envOrObj, maybeObj) {
                var resolved = _resolveEnvAndRef.apply(null, arguments);
                var obj = resolved.ref;
                if (obj.toString() === "0x0") {
                    return null;
                }
                return _api._getObjectClassName(resolved.env, obj);
            },
            getDirectBufferAddress: function(envOrBuffer, maybeBuffer) {
                var resolved = _resolveEnvAndRef.apply(null, arguments);
                var raw = _getDirectBufferAddressFn(resolved.env)(resolved.env, resolved.ref);
                if (raw === null || raw === undefined) {
                    return null;
                }
                return _toPtr(raw);
            },
            getDirectBufferCapacity: function(envOrBuffer, maybeBuffer) {
                var resolved = _resolveEnvAndRef.apply(null, arguments);
                return _getDirectBufferCapacityFn(resolved.env)(resolved.env, resolved.ref);
            }
        };
    }

    var _sizeof = {
        pointer: _POINTER_SIZE,
        jvalue: 8,
        JNINativeMethod: _POINTER_SIZE * 3
    };

    var _structs = {
        JNINativeMethod: {
            size: _sizeof.JNINativeMethod,
            read: function(address) {
                return _readJNINativeMethod(address);
            },
            readArray: function(address, count) {
                return _readJNINativeMethods(address, count);
            }
        },
        jvalue: {
            size: _sizeof.jvalue,
            read: function(address, jniType) {
                return _readJvalue(address, jniType);
            },
            readArray: function(address, typesOrSig) {
                return _readJvalueArray(address, typesOrSig);
            }
        }
    };

    _api.entries = function(env) {
        return arguments.length === 0 ? _getEntries() : _getEntries(env);
    };
    _api.find = function(envOrName, maybeName) {
        var resolved = _resolveEnvAndName.apply(null, arguments);
        return _makeEntry(resolved.env, resolved.name, false);
    };
    _api.addr = function(envOrName, maybeName) {
        return _getAddress.apply(null, arguments);
    };
    _api.pointerSize = _POINTER_SIZE;
    _api.env = _makeEnvHelper();
    _api.sizeof = _sizeof;
    _api.structs = _structs;

    Object.defineProperty(_api, "table", {
        configurable: true,
        enumerable: true,
        get: function() {
            return _getTable();
        }
    });

    globalThis.Jni = new Proxy(_api, {
        get: function(target, prop) {
            if (typeof prop === "string" && !(prop in target)) {
                if (_getIndex(prop, true) !== null) {
                    return _getAddress(prop);
                }
            }

            return target[prop];
        },
        ownKeys: function(target) {
            var keys = Object.keys(target);
            for (var i = 0; i < _JNI_NAMES.length; i++) {
                keys.push(_JNI_NAMES[i]);
            }

            return keys;
        },
        getOwnPropertyDescriptor: function(target, prop) {
            if (typeof prop === "string" && !(prop in target)) {
                if (_getIndex(prop, true) !== null) {
                    return {
                        configurable: true,
                        enumerable: true,
                        writable: false,
                        value: _getAddress(prop)
                    };
                }
            }

            return Object.getOwnPropertyDescriptor(target, prop);
        }
    });
})();
