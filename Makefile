ifeq (,$(FSTAR_HOME))
  $(error FSTAR_HOME is not defined)
endif

ifeq (,$(KREMLIN_HOME))
  $(error KREMLIN_HOME is not defined)
endif

ifeq (,$(HACL_HOME))
  $(error HACL_HOME is not defined)
endif

SOURCE_DIRS = .

FSTAR_ROOTS = Spec.Test.fst

include $(HACL_HOME)/Makefile.local

INCLUDE_DIRS += \
  $(ALL_HACL_DIRS) \
  $(SOURCE_DIRS) \
  $(FSTAR_HOME)/ulib/.cache \
  $(KREMLIN_HOME)/kremlib

FSTAR_INCLUDES = $(addprefix --include ,$(INCLUDE_DIRS))

OTHERFLAGS = --admit_smt_queries true \
             --cache_checked_modules $(FSTAR_INCLUDES) \
             --already_cached 'Prims FStar LowStar C Spec.Loops TestLib WasmSupport Hacl' \
             --use_extracted_interfaces true \
             --no_load_fstartaclib
