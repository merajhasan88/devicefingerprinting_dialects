// Minimal stand-in for <jni.h> so code_integrity.cpp compiles on a Linux host
// for tools/native/check_code_integrity.cpp. Not used by the Android build.
#pragma once
#include <string.h>
#define JNIEXPORT
#define JNICALL
typedef const char *jstring;
typedef void *jobject;
struct JNIEnv { const char *NewStringUTF(const char *s) { return strdup(s); } };
