#!/bin/sh
##-=======================================================-##
##							[+] Xe1phix-ProcFS-Memory-Info.sh
##-=======================================================-##
## ------------------------------------------------------------------------------------------------------------------------------------- ##
export TempDir='mktemp --tempdir=tmp.XXXXXXXXXX'
## ------------------------------------------------------------------------------------------------------------------------------------- ##
MemAvailable=`cat -vET /proc/meminfo |grep MemAvailable:`
MemBuffers=`cat -vET /proc/meminfo |grep Buffers:`
MemCached=`cat -vET /proc/meminfo |grep Cached:`
MemSwapCached=`cat -vET /proc/meminfo |grep SwapCached:`
MemActive=`cat -vET /proc/meminfo |grep Active:`
MemInActive=`cat -vET /proc/meminfo |grep Inactive:`
MemKernelStack=`cat -vET /proc/meminfo |grep KernelStack:`
MemPageTables=`cat -vET /proc/meminfo |grep PageTables:`
MemVmallocTotal=`cat -vET /proc/meminfo |grep VmallocTotal:`
MemVmallocUsed=`cat -vET /proc/meminfo |grep VmallocUsed:`
MemVmallocChunk=`cat -vET /proc/meminfo |grep VmallocChunk:`
MemSwapTotal=`cat -vET /proc/meminfo |grep SwapTotal:`
MemSwapFree=`cat -vET /proc/meminfo |grep SwapFree:`
MemShMem=`cat -vET /proc/meminfo |grep ShMem:`
MemHugepagesize=`cat -vET /proc/meminfo |grep Hugepagesize:`
## ------------------------------------------------------------------------------------------------------------------------------------- ##
MemAvailable=`cat -vET /proc/meminfo |grep MemAvailable: >> $TempDir/Mem/MemAvailable`
MemBuffers=`cat -vET /proc/meminfo |grep Buffers: >> $TempDir/Mem/Buffers`
MemCached=`cat -vET /proc/meminfo |grep Cached: >> $TempDir/Mem/Cached`
MemSwapCached=`cat -vET /proc/meminfo |grep SwapCached: >> $TempDir/Mem/SwapCached`
MemActive=`cat -vET /proc/meminfo |grep Active: >> $TempDir/Mem/Active`
MemInActive=`cat -vET /proc/meminfo |grep Inactive: >> $TempDir/Mem/Inactive`
MemKernelStack=`cat -vET /proc/meminfo |grep KernelStack: >> $TempDir/Mem/KernelStack`
MemPageTables=`cat -vET /proc/meminfo |grep PageTables: >> $TempDir/Mem/PageTables`
MemVmallocTotal=`cat -vET /proc/meminfo |grep VmallocTotal: >> $TempDir/Mem/VmallocTotal`
MemVmallocUsed=`cat -vET /proc/meminfo |grep VmallocUsed: >> $TempDir/Mem/VmallocUsed`
MemVmallocChunk=`cat -vET /proc/meminfo |grep VmallocChunk: >> $TempDir/Mem/VmallocChunk`
MemSwapTotal=`cat -vET /proc/meminfo |grep SwapTotal: >> $TempDir/Mem/SwapTotal`
MemSwapFree=`cat -vET /proc/meminfo |grep SwapFree: >> $TempDir/Mem/SwapFree`
MemShMem=`cat -vET /proc/meminfo |grep ShMem: >> $TempDir/Mem/ShMem`
MemHugepagesize=`cat -vET /proc/meminfo |grep Hugepagesize: >> $TempDir/Mem/Hugepagesize`
## ------------------------------------------------------------------------------------------------------------------------------------- ##
