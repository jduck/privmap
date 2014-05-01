LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
  privmap.c

LOCAL_MODULE := privmap

include $(BUILD_STATIC_EXECUTABLE)
include $(BUILD_EXECUTABLE)
include $(call all-makefiles-under,$(LOCAL_PATH))
