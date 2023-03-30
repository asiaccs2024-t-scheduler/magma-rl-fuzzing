#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

git clone https://github.com/icse2024-t-scheduler/t-scheduler.git "$FUZZER/repo"

patch -p1 -d "$FUZZER/repo" << EOF
--- a/utils/aflpp_driver/aflpp_driver.c
+++ b/utils/aflpp_driver/aflpp_driver.c
@@ -57,12 +57,12 @@ $AFL_HOME/afl-fuzz -i IN -o OUT ./a.out
   #include "hash.h"
 #endif

-int                   __afl_sharedmem_fuzzing = 1;
+int                   __afl_sharedmem_fuzzing = 0;
 extern unsigned int  *__afl_fuzz_len;
 extern unsigned char *__afl_fuzz_ptr;

 // libFuzzer interface is thin, so we don't include any libFuzzer headers.
-int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
+__attribute__((weak)) int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
 __attribute__((weak)) int LLVMFuzzerInitialize(int *argc, char ***argv);

 // Default nop ASan hooks for manual posisoning when not linking the ASan
@@ -87,7 +87,7 @@ __attribute__((weak)) void __asan_unpoison_memory_region(
 __attribute__((weak)) void *__asan_region_is_poisoned(void *beg, size_t size);

 // Notify AFL about persistent mode.
-static volatile char AFL_PERSISTENT[] = "##SIG_AFL_PERSISTENT##";
+static volatile char AFL_PERSISTENT[] = "##SIG_AFL_NOT_PERSISTENT##";
 int                  __afl_persistent_loop(unsigned int);

 // Notify AFL about deferred forkserver.
@@ -245,7 +245,7 @@ static int ExecuteFilesOnyByOne(int argc, char **argv) {

 }

-int main(int argc, char **argv) {
+__attribute__((weak)) int main(int argc, char **argv) {

   if (argc < 2 || strncmp(argv[1], "-h", 2) == 0)
     printf(
@@ -372,3 +372,7 @@ int main(int argc, char **argv) {

 }

+__attribute__((weak))
+int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
+  return 0;
+}
EOF
