TARGET = simulator:clang:latest:15.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = QMCDumper

QMCDumper_FILES = Tweak.xm
QMCDumper_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/tweak.mk