ARCHS = arm64 
FINALPACKAGE = 1
FOR_RELEASE = 1
WARNINGS = 1
GO_EASY_ON_ME = 1

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = abc

$(TWEAK_NAME)_FRAMEWORKS = UIKit Accelerate Foundation QuartzCore CoreGraphics AudioToolbox CoreText Metal MobileCoreServices Security SystemConfiguration IOKit CoreTelephony CoreImage CFNetwork AdSupport AVFoundation
$(TWEAK_NAME)_CCFLAGS = -fno-rtti -fvisibility=hidden -DNDEBUG -std=c++11
$(TWEAK_NAME)_CFLAGS = -fobjc-arc -Wno-deprecated-declarations -Wno-unused-variable -Wno-unused-value  -DHAVE_INTTYPES_H -DHAVE_PKCRYPT -DHAVE_STDINT_H -DHAVE_WZAES -DHAVE_ZLIB  
$(TWEAK_NAME)_LDFLAGS +=  -lresolv -lz -liconv lib/libdaubuoi.a lib/libmonostring.a 
$(TWEAK_NAME)_FILES = imguidraw.mm $(wildcard FileKoRac/*.mm) $(wildcard FileKoRac/*.m) $(wildcard FileRac/*.m) $(wildcard FileRac/*.mm) $(wildcard IMGUI/*.cpp) $(wildcard IMGUI/*.mm) 
$(TWEAK_NAME)_LOGOS_DEFAULT_GENERATOR = internal
include $(THEOS_MAKE_PATH)/tweak.mk

# Theme by: Thiện 131 
# Share by: @dothanh1110 (đc cấp phép)
# mấy con chó share ko gắn nguồn chết đi || và mấy con chó leak trc đó cx thế nhé
# Zalo: https://zalo.me/g/pmselp698