
# Fuzzing excelcnv

Here are my notes for fuzzing excelcnv:




Ok, so it is time to fuzz excelcnv

https://www.sstic.org/media/SSTIC2020/SSTIC-actes/hacking_excel_online_-_how_to_exploit_calc/SSTIC2020-Article-hacking_excel_online_-_how_to_exploit_calc-joly.pdf?utm_source=chatgpt.com

Here is the initialization. We can see that it tries loading the excelcvn.exe.config file, but this file does not exist.


```
Breakpoint 1 hit
KERNEL32!CreateFileW:
00007fff`a6747270 ff25c2140300    jmp     qword ptr [KERNEL32!_imp_CreateFileW (00007fff`a6778738)] ds:00007fff`a6778738={KERNELBASE!CreateFileW (00007fff`a5398910)}
0:000> du @rcx
00000183`d0d8ddb0  "C:\Program Files\Microsoft Offic"
00000183`d0d8ddf0  "e\root\Office16\excelcnv.exe.con"
00000183`d0d8de30  "fig"
0:000> k
 # Child-SP          RetAddr               Call Site
00 0000004a`6aefc5d8 00007fff`8b98353a     KERNEL32!CreateFileW
01 0000004a`6aefc5e0 00007fff`8b972729     mscoreei!CreateConfigStream+0x10a
02 0000004a`6aefc640 00007fff`8b9760a4     mscoreei!RuntimeRequest::ParseComponentConfig+0xd5
03 0000004a`6aefc6f0 00007fff`8b974f3b     mscoreei!RuntimeRequest::ComputeVersionStringThrowing+0xf0c
04 0000004a`6aefccf0 00007fff`8b978d4a     mscoreei!RuntimeRequest::ComputeVersionString+0x23
05 0000004a`6aefcd70 00007fff`8d687621     mscoreei!GetRequestedRuntimeInfo+0x24a
06 0000004a`6aefcf10 00007ffe`d4412eb7     mscoree!ShellShim_GetRequestedRuntimeInfo+0x231
07 0000004a`6aefcf90 00007ffe`d4411d0f     mso98win32client!FindCsiDllMsi+0x34f
08 0000004a`6aefd060 00007ffe`d4460459     mso98win32client!HostClrLiblet::Init+0x2f
09 0000004a`6aefd090 00007ffe`ae7b67d6     mso98win32client!Mso::LibletAPI::InitLiblets+0x79
0a 0000004a`6aefd0c0 00007ff7`b75dc53f     mso!MsoFInitOfficeEx2+0x96
0b 0000004a`6aefd150 00007ff7`b754d7b3     ExcelCnv!Excel::XlMso::FInitOffice96+0xc7
0c 0000004a`6aefd1e0 00007ff7`b85776d2     ExcelCnv!FMainInit+0x612
0d 0000004a`6aeff3f0 00007ff7`b749e919     ExcelCnv!FWinInit+0x38e
0e 0000004a`6aeff6a0 00007ff7`b7d41dd2     ExcelCnv!WinMain+0x49c
0f 0000004a`6aeffdf0 00007fff`a671e8d7     ExcelCnv!_imp_load_RmGetList+0x205
10 0000004a`6aeffe30 00007fff`a81f14fc     KERNEL32!BaseThreadInitThunk+0x17
11 0000004a`6aeffe60 00000000`00000000     ntdll!RtlUserThreadStart+0x2c

```


```


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void WinMain(undefined8 param_1,undefined8 param_2,char *param_3,undefined4 param_4)

{
  longlong *plVar1;
  longlong lVar2;
  code *pcVar3;
  char cVar4;
  byte bVar5;
  byte bVar6;
  byte bVar7;
  undefined uVar8;
  byte bVar9;
  int iVar10;
  undefined4 uVar11;
  int iVar12;
  longlong lVar13;
  undefined8 uVar14;
  short *psVar15;
  undefined8 uVar16;
  uint uVar17;
  int iVar18;
  uint uVar19;
  byte bVar20;
  int iVar21;
  longlong unaff_GS_OFFSET;
  undefined auStack_748 [32];
  char **ppcStack_728;
  undefined **ppuStack_720;
  undefined **ppuStack_718;
  undefined **ppuStack_710;
  char cStack_708;
  char cStack_707;
  undefined4 uStack_704;
  int iStack_700;
  int iStack_6fc;
  char *pcStack_6f8;
  short *psStack_6f0;
  undefined4 uStack_6e8;
  char *pcStack_6e0;
  short *psStack_6d8;
  undefined auStack_6d0 [24];
  undefined *puStack_6b8;
  undefined *puStack_6b0;
  undefined *puStack_6a8;
  undefined8 uStack_6a0;
  undefined8 uStack_698;
  undefined8 uStack_690;
  undefined8 uStack_688;
  undefined8 uStack_680;
  undefined *puStack_678;
  undefined *puStack_670;
  undefined8 uStack_668;
  undefined4 uStack_660;
  undefined4 uStack_65c;
  undefined4 uStack_658;
  undefined4 uStack_654;
  undefined4 uStack_650;
  undefined4 uStack_64c;
  undefined8 uStack_648;
  undefined8 uStack_640;
  undefined *puStack_638;
  undefined *puStack_630;
  undefined8 uStack_628;
  undefined8 uStack_620;
  undefined8 uStack_618;
  undefined8 uStack_610;
  undefined8 uStack_608;
  undefined8 uStack_600;
  undefined *puStack_5f8;
  undefined *puStack_5f0;
  undefined8 uStack_5e8;
  undefined8 uStack_5e0;
  undefined8 uStack_5d8;
  undefined8 uStack_5d0;
  undefined8 uStack_5c8;
  undefined8 uStack_5c0;
  undefined *puStack_5b8;
  undefined *puStack_5b0;
  undefined *puStack_5a8;
  undefined8 uStack_5a0;
  undefined8 uStack_598;
  undefined8 uStack_590;
  undefined8 uStack_588;
  undefined8 uStack_580;
  undefined *puStack_578;
  undefined *puStack_570;
  undefined8 uStack_568;
  undefined4 uStack_560;
  undefined4 uStack_55c;
  undefined8 uStack_558;
  undefined8 uStack_550;
  undefined8 uStack_548;
  undefined8 uStack_540;
  undefined8 uStack_538;
  undefined4 uStack_530;
  undefined4 uStack_52c;
  undefined2 uStack_528;
  undefined2 uStack_47e;
  undefined4 uStack_478;
  undefined4 uStack_474;
  undefined8 uStack_470;
  undefined4 uStack_468;
  undefined4 uStack_464;
  undefined8 uStack_460;
  undefined8 uStack_458;
  undefined8 uStack_450;
  undefined4 uStack_448;
  undefined4 uStack_444;
  undefined8 uStack_440;
  undefined4 uStack_438;
  undefined4 uStack_434;
  undefined8 uStack_430;
  undefined8 uStack_428;
  undefined8 uStack_420;
  undefined8 uStack_418;
  undefined8 uStack_410;
  undefined8 uStack_408;
  undefined8 uStack_400;
  undefined8 uStack_3f8;
  undefined8 uStack_3f0;
  undefined8 uStack_3e8;
  undefined8 uStack_3e0;
  undefined8 uStack_3d8;
  undefined8 uStack_3d0;
  undefined4 uStack_3c8;
  undefined4 uStack_3c4;
  undefined8 uStack_3c0;
  undefined4 uStack_3b8;
  undefined4 uStack_3b4;
  undefined8 uStack_3b0;
  undefined8 uStack_3a8;
  undefined8 uStack_3a0;
  undefined4 uStack_398;
  undefined4 uStack_394;
  undefined8 uStack_390;
  undefined4 uStack_388;
  undefined4 uStack_384;
  undefined8 uStack_380;
  undefined8 uStack_378;
  undefined8 uStack_370;
  undefined8 uStack_368;
  undefined8 uStack_360;
  undefined8 uStack_358;
  undefined8 uStack_350;
  undefined8 uStack_348;
  undefined8 uStack_340;
  undefined8 uStack_338;
  undefined8 uStack_330;
  undefined8 uStack_328;
  undefined8 uStack_320;
  undefined auStack_318 [176];
  undefined auStack_268 [176];
  undefined auStack_1b8 [176];
  undefined auStack_108 [176];
  ulonglong uStack_58;

  uStack_58 = ___security_cookie ^ (ulonglong)auStack_748;
  uStack_6e8 = param_4;
  pcStack_6e0 = param_3;
  _DAT_1429ee7f4 = GetCurrentThreadId();
  ?InitGlobalsMechanisms@@YAXXZ();
  _?m_hinstPrev@ROGLOBALSCONTAINER@ROGLOBALS@@0PEAUHINSTANCE__@@EA = param_2;
  _?m_hinstApp@ROGLOBALSCONTAINER@ROGLOBALS@@0PEAUHINSTANCE__@@EA = param_1;
  _?m_dwMainThreadId@ROGLOBALSCONTAINER@ROGLOBALS@@0KA = GetCurrentThreadId();
  _?m_renderMode@ROGLOBALSCONTAINER@ROGLOBALS@@0W4RENDERMODE@@A = 1;
  _?m_hdcScreen@ROGLOBALSCONTAINER@ROGLOBALS@@0PEAUHDC__@@EA = GetDC(0);
  lVar13 = ?Load@DllData@LoadMso@Mso@@QEAAPEAUHINSTANCE__@@_N@Z(0x142984ae0,0);
  uVar19 = 0;
  if (lVar13 == 0) {
    lVar13 = IsolationAwareLoadLibraryW(&??_C@_1BA@OEHEAECL@?$AAm?$AAs?$AAo?$AA?4?$AAd?$AAl?$AAl@ );
    if (lVar13 == 0) goto LAB_14000e9cb;
  }
  iVar10 = ?FWringerFromCmdLine@ConverterContext@@SAHXZ();
  if (iVar10 != 0) {
    Ordinal_10006();
  }
  Ordinal_55331(auStack_6d0,0x1429c2610,1);
  uStack_704 = 0;
  InitPerformanceDLL();
  ?InstallBootExceptionHandler@@YAXXZ();
  Ordinal_46993();
  Ordinal_29723();
  bVar5 = 0;
  cStack_707 = '\0';
  cStack_708 = '\0';
  _?szWindowTitle@@3PA_WA = 0x69004d;
  uRam00000001429984a4 = 0x720063;
  uRam00000001429984a8 = 0x73006f;
  uRam00000001429984ac = 0x66006f;
  _DAT_1429984b0 = 0x200074;
  uRam00000001429984b4 = 0x780045;
  uRam00000001429984b8 = 0x650063;
  uRam00000001429984bc = 0x6c;
  uVar14 = GetCommandLineW();
  uVar14 = ?GetUnicodeCmdLine@@YAPEA_WPEA_W@Z(uVar14);
  psVar15 = (short *)?RemoveExtraSpaceForUnicode@@YAPEA_WPEA_W@Z(uVar14);
  if ((param_3 == (char *)0x0) || (bVar6 = bVar5, *param_3 == '\0')) {
    bVar6 = 1;
  }
  psStack_6d8 = psVar15;
  cVar4 = ?FUseUnicode@CommandLineParsing@SecuritySettings@@YA_NXZ();
  bVar20 = bVar6;
  if (cVar4 == '\0') {
LAB_14000e603:
    bVar7 = bVar20;
    if (bVar20 != 0) goto LAB_14000e60c;
    uStack_478 = 0;
    uStack_474 = 0x53;
    uStack_470 = 0;
    uStack_468 = 0;
    uStack_444 = 0x45;
    uStack_434 = 0x65;
    uStack_464 = 0x73;
    uStack_418 = 0xb;
    uStack_3b4 = 0x73;
    uStack_394 = 0x45;
    uStack_384 = 0x65;
    uStack_368 = 0xb;
    uStack_460 = 0;
    uStack_458 = 9;
    uStack_450 = 0;
    uStack_448 = 0;
    uStack_440 = 0;
    uStack_438 = 0;
    uStack_430 = 0;
    uStack_428 = 8;
    uStack_420 = 0;
    uStack_410 = 0;
    uStack_408 = 10;
    uStack_400 = 0;
    uStack_3f8 = 4;
    uStack_3f0 = 0;
    uStack_3e8 = 0xc;
    uStack_3e0 = 0;
    uStack_3d8 = 0x10;
    uStack_3d0 = 0;
    uStack_3c8 = 0;
    uStack_3c4 = 0x53;
    uStack_3c0 = 0;
    uStack_3b8 = 0;
    uStack_3b0 = 0;
    uStack_3a8 = 9;
    uStack_3a0 = 0;
    uStack_398 = 0;
    uStack_390 = 0;
    uStack_388 = 0;
    uStack_380 = 0;
    uStack_378 = 8;
    uStack_370 = 0;
    uStack_360 = 0;
    uStack_358 = 10;
    uStack_350 = 0;
    uStack_348 = 4;
    uStack_340 = 0;
    uStack_338 = 0xc;
    uStack_330 = 0;
    uStack_328 = 0x10;
    uStack_320 = 0;
    pcStack_6f8 = param_3;
    psStack_6f0 = psVar15;
    cVar4 = ?FUseUnicode@CommandLineParsing@SecuritySettings@@YA_NXZ();
    if (cVar4 == '\0') {
      Ordinal_21605(&uStack_478,0xb,&pcStack_6f8,0);
    }
    else {
      iVar10 = Ordinal_21605();
      if (iVar10 != 0) {
        Ordinal_18329(&uStack_3c8,0xb,&psStack_6f0,0);
      }
    }
    bVar5 = ?FCheckExists@@YA_NAEBUARGC@@0@Z(&uStack_3a8,&uStack_458);
    bVar6 = ?FCheckExists@@YA_NAEBUARGC@@0@Z(&uStack_3b8,&uStack_468);
    bVar7 = ?FCheckExists@@YA_NAEBUARGC@@0@Z(&uStack_3c8,&uStack_478);
    lVar13 = **(longlong **)(unaff_GS_OFFSET + 0x58);
    *(uint *)(*(longlong *)(lVar13 + 0x10) + 0x98c) = (uint)(byte)(bVar7 | bVar6 | bVar5);
    bVar5 = ?FCheckExists@@YA_NAEBUARGC@@0@Z(&uStack_358,&uStack_408);
    bVar6 = ?FCheckExists@@YA_NAEBUARGC@@0@Z(&uStack_388,&uStack_438);
    bVar7 = ?FCheckExists@@YA_NAEBUARGC@@0@Z(&uStack_398,&uStack_448);
    bVar7 = bVar7 | bVar6 | bVar5;
    *(uint *)(*(longlong *)(lVar13 + 0x10) + 0x654) = (uint)bVar7;
    bVar5 = ?FCheckExists@@YA_NAEBUARGC@@0@Z(&uStack_378,&uStack_428);
    *(uint *)(*(longlong *)(lVar13 + 0x10) + 0x6ec) = (uint)(bVar5 | bVar7);
    bVar5 = ?FCheckExists@@YA_NAEBUARGC@@0@Z(&uStack_368,&uStack_418);
    *(uint *)(*(longlong *)(lVar13 + 0x10) + 0x974) = (uint)bVar5;
    cVar4 = ?FCheckExists@@YA_NAEBUARGC@@0@Z(&uStack_358,&uStack_408);
    uVar17 = uVar19;
    if ((((cVar4 != '\0') &&
         (cVar4 = ?FCheckExists@@YA_NAEBUARGC@@0@Z(&uStack_398,&uStack_448), cVar4 == '\0')) &&
        (cVar4 = ?FCheckExists@@YA_NAEBUARGC@@0@Z(&uStack_388,&uStack_438), cVar4 == '\0')) &&
       (cVar4 = ?FCheckExists@@YA_NAEBUARGC@@0@Z(&uStack_378,&uStack_428), cVar4 == '\0')) {
      uVar17 = 1;
    }
    *(uint *)(*(longlong *)(lVar13 + 0x10) + 0x658) = uVar17;
    DAT_1429c42c9 = (undefined)uVar17;
    cVar4 = ?FCheckExists@@YA_NAEBUARGC@@0@Z(&uStack_378,&uStack_428);
    if (cVar4 == '\0') {
      cVar4 = ?FCheckExists@@YA_NAEBUARGC@@0@Z(&uStack_348,&uStack_3f8);
      if (cVar4 != '\0') goto LAB_14000f01a;
    }
    else {
LAB_14000f01a:
      Ordinal_32216(2);
    }
    cVar4 = ?FCheckExists@@YA_NAEBUARGC@@0@Z(&uStack_338,&uStack_3e8);
    if (cVar4 != '\0') {
      Ordinal_54014();
    }
    uVar8 = ?FCheckExists@@YA_NAEBUARGC@@0@Z(&uStack_328,&uStack_3d8);
    Ordinal_53415(uVar8);
    if ((*(int *)(*(longlong *)(lVar13 + 0x10) + 0x6ec) != 0) ||
       (cVar4 = ?FCheckExists@@YA_NAEBUARGC@@0@Z(&uStack_348,&uStack_3f8), cVar4 != '\0')) {
      uStack_704._0_2_ = CONCAT11(1,(undefined)uStack_704);
    }
    lVar2 = *(longlong *)(lVar13 + 0x10);
    uVar8 = uStack_704._2_1_;
    if (*(int *)(lVar2 + 0x98c) != 0) {
      uVar8 = 1;
    }
    uStack_704._0_3_ = CONCAT12(uVar8,(undefined2)uStack_704);
    lVar13 = **(longlong **)(unaff_GS_OFFSET + 0x58);
    if ((*(int *)(lVar2 + 0x658) != 0) || (*(int *)(lVar2 + 0x974) != 0)) {
      uStack_704 = CONCAT13(1,(undefined3)uStack_704);
    }
    cStack_707 = ?FCheckExists@@YA_NAEBUARGC@@0@Z(&uStack_348,&uStack_3f8);
    cStack_708 = ?FCheckExists@@YA_NAEBUARGC@@0@Z(&uStack_378,&uStack_428);
  }
  else {
    bVar7 = 1;
    if ((psVar15 == (short *)0x0) || (bVar9 = bVar5, *psVar15 == 0)) {
      bVar9 = 1;
    }
    bVar20 = bVar5;
    if ((bVar6 == 0) || (bVar9 == 0)) goto LAB_14000e603;
LAB_14000e60c:
    lVar13 = **(longlong **)(unaff_GS_OFFSET + 0x58);
    lVar2 = *(longlong *)(lVar13 + 0x10);
    *(undefined4 *)(lVar2 + 0x98c) = 0;
    *(undefined8 *)(lVar2 + 0x654) = 0;
    *(undefined4 *)(lVar2 + 0x6ec) = 0;
    Ordinal_5503();
    uStack_704 = CONCAT31(uStack_704._1_3_,1);
    bVar20 = bVar7;
  }
  Ordinal_11612();
  Ordinal_44474(&uStack_704);
  plVar1 = (longlong *)(lVar13 + 0x10);
  if ((*(int *)(*plVar1 + 0x6ec) != 0) &&
     ((*(int *)(*plVar1 + 0x658) == 0 ||
      (iVar10 = ?FIsFileFormatFBDFeatureEnabled@@YAHXZ(), iVar10 == 0)))) {
    uVar19 = 0x80000000;
  }
  iVar10 = *(int *)(*plVar1 + 0x98c);
  Ordinal_27911(3);
  Ordinal_48782(1);
  ppcStack_728 = (char **)CONCAT44(ppcStack_728._4_4_,1);
  uVar11 = Ordinal_58822((uint)bVar20 << 0x1e | ~-(uint)(iVar10 != 0) & 2 | uVar19,
                         &??_C@_05HGMNBLAA@Excel@,
                         &?vppxpsa@@3PEAU?$T_MSOPX@PEAUMSOSTARTUPACTION@@@Plex@DoNotUse@Mso@@EA, 0);
  *(undefined4 *)(*plVar1 + 0x98c) = uVar11;
  iVar12 = Ordinal_309(&?vmsoridGridLineScaleByDpi@@3U_msoreg@@B);
  uVar14 = 0;
  iVar10 = 0;
  ?s_fScaleGridlinesAt300AndAbove@DpiAdapter@@0_NA = iVar12 != 0;
  ?DpiScaleFactorSystem@DpiAdapter@@SAMXZ();
  ?s_fScaleGridlinesSystemDpi@DpiAdapter@@0_NA =
       ?FShouldScaleGridlinesAtDpiScaleFactor@DpiAdapter@@CA_NM@Z();
  _DAT_1429c4308 = 0;
  ?InitEarlyOffice@@YAXXZ();
  Ordinal_18928(1);
  iVar12 = ?HrInitSharedCode@@YAJPEAVIMemHeap@@@Z
                     (&?m_memheapMain@TSGLOBALSCONTAINER@TSGLOBALS@@0VCommonMemoryHeap@@A);
  if (-1 < iVar12) {
    iStack_6fc = Ordinal_47338();
    lVar2 = *plVar1;
    *(undefined4 *)(lVar2 + 0xb9c) = 0;
    *(undefined4 *)(lVar2 + 0xba8) = 0;
    uVar11 = GetUserDefaultLCID();
    pcStack_6f8 = (char *)CONCAT44(pcStack_6f8._4_4_,iStack_6fc);
    psStack_6f0 = (short *)CONCAT44(psStack_6f0._4_4_,uVar11);
    iVar12 = FUN_14000daf0(auStack_108,auStack_318,auStack_1b8);
    if (iVar12 == 0) {
      iVar12 = FUN_14000dd60(&psStack_6f0,&iStack_6fc,&pcStack_6f8);
      if (iVar12 == 0) {
        uVar11 = (int)psStack_6f0;
      }
      else {
        iStack_6fc = FUN_1406b34b0(iStack_6fc);
        lVar2 = *(longlong *)(lVar13 + 0x10);
        *(undefined4 *)(lVar2 + 0xb9c) = 1;
        *(int *)(lVar2 + 0xba0) = (int)psStack_6f0;
        *(int *)(lVar2 + 0xb94) = iStack_6fc;
        *(int *)(lVar2 + 0xb98) = (int)pcStack_6f8;
        uVar11 = (int)psStack_6f0;
      }
    }
    else {
      puStack_638 = &??_7?$ClassifiedStructuredObject@PEB_W@Diagnostics@Mso@@6B@;
      uStack_610 = 0;
      puStack_5b8 = &??_7?$ClassifiedStructuredObject@PEB_W@Diagnostics@Mso@@6B@;
      uStack_590 = 0;
      puStack_578 = &??_7?$ClassifiedStructuredObject@PEB_W@Diagnostics@Mso@@6B@;
      puStack_630 = &??_C@_0BA@MGADLHHN@hcultureTagInst@;
      uStack_550 = 0;
      uStack_628 = auStack_1b8;
      uStack_618 = 0;
      puStack_5f8 = &??_7?$ClassifiedStructuredObject@PEB_W@Diagnostics@Mso@@6B@;
      puStack_5f0 = &??_C@_0BA@MGADLHHN@hcultureTagInst@;
      puStack_5b0 = &??_C@_0O@PNEHOCGI@hcultureTagUi@;
      puStack_6a8 = auStack_318;
      puStack_570 = &??_C@_0BA@IPJBDKPI@hcultureTagUser@;
      uStack_568 = auStack_108;
      ppuStack_710 = &puStack_5f8;
      ppuStack_718 = &puStack_6b8;
      uStack_5d8 = 0;
      uStack_5d0 = 0;
      ppuStack_720 = &puStack_678;
      puStack_6b8 = &??_7?$ClassifiedStructuredObject@PEB_W@Diagnostics@Mso@@6B@;
      puStack_6b0 = &??_C@_0O@PNEHOCGI@hcultureTagUi@;
      uStack_620 = CONCAT62(uStack_620._2_6_,4);
      uStack_5e0 = uStack_620;
      uStack_598 = 0;
      uStack_698 = 0;
      uStack_690 = 0;
      puStack_678 = &??_7?$ClassifiedStructuredObject@PEB_W@Diagnostics@Mso@@6B@;
      puStack_670 = &??_C@_0BA@IPJBDKPI@hcultureTagUser@;
      uStack_5a0 = CONCAT62(uStack_5a0._2_6_,4);
      uStack_6a0 = uStack_5a0;
      uStack_560 = CONCAT22(uStack_560._2_2_,4);
      uStack_558 = 0;
      ppcStack_728 = (char **)&
                              ??_C@_1DG@OCHBJGEO@?$AAX?$AAl?$AAM?$AAa?$AAi?$AAn?$AA?3?$AA?5?$AAh?$AA c?$AAu?$AAl?$AAt?$AAu?$AAr@
      ;
      uStack_608 = 0;
      uStack_600 = 7;
      uStack_588 = 0;
      uStack_580 = 7;
      uStack_548 = 0;
      uStack_540 = 7;
      uStack_5c8 = 0;
      uStack_5c0 = 7;
      uStack_688 = 0;
      uStack_680 = 7;
      uStack_660 = uStack_560;
      uStack_65c = uStack_55c;
      uStack_658 = 0;
      uStack_654 = 0;
      uStack_650 = 0;
      uStack_64c = 0;
      uStack_648 = 0;
      uStack_640 = 7;
      uStack_5e8 = uStack_628;
      puStack_5a8 = puStack_6a8;
      uStack_668 = uStack_568;
      ?SendTraceTag@XlsDiag@@SAXKW4Category@Logging@Mso@@W4Severity@34@W4DataClassifications@34@PEB_ WZZ
                (0x2059f313,0x354,0x32,4);
      ?_Tidy_deallocate@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@AEAAXXZ
                (&uStack_558);
      ?_Tidy_deallocate@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@AEAAXXZ
                (&uStack_598);
      ?_Tidy_deallocate@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@AEAAXXZ
                (&uStack_618);
      iVar12 = ?LcidGetLcidFromTag@IntlUtil@@YAKPEB_W@Z(auStack_318);
      iStack_700 = iVar12;
      FUN_1410f8c60(&iStack_700);
      if (iVar12 != iStack_700) {
        uStack_618 = 0;
        uStack_620 = 0;
        uStack_5d8 = 0;
        puStack_638 = &??_7?$ClassifiedStructuredObject@H@Diagnostics@Mso@@6B@;
        puStack_630 = &??_C@_0L@OMPFPMAF@lcidActual@;
        puStack_5f8 = &??_7?$ClassifiedStructuredObject@H@Diagnostics@Mso@@6B@;
        puStack_5f0 = &??_C@_06MLEPBGJL@lcidUI@;
        uStack_610 = 0;
        uStack_608 = 7;
        ppuStack_718 = &puStack_5b8;
        uStack_628._0_6_ = CONCAT24(4,iStack_700);
        puStack_5b8 = &??_7?$ClassifiedStructuredObject@H@Diagnostics@Mso@@6B@;
        puStack_5b0 = &??_C@_0L@OMPFPMAF@lcidActual@;
        ppuStack_720 = &puStack_578;
        puStack_5a8 = uStack_628;
        uStack_5a0 = 0;
        uStack_598 = 0;
        uStack_590 = 0;
        uStack_588 = 7;
        uStack_5d0 = 0;
        uStack_5c8 = 7;
        uStack_5e8._0_6_ = CONCAT24(4,iVar12);
        puStack_578 = &??_7?$ClassifiedStructuredObject@H@Diagnostics@Mso@@6B@;
        puStack_570 = &??_C@_06MLEPBGJL@lcidUI@;
        uStack_5e0 = 0;
        ppcStack_728 = (char **)&
                                ??_C@_1DM@BFHIIDEA@?$AAX?$AAl?$AAM?$AAa?$AAi?$AAn?$AA?3?$AA?5?$AAl?$ AAc?$AAi?$AAd?$AAU?$AAI?$AA?5@
        ;
        uStack_558 = 0;
        uStack_550 = 0;
        uStack_568 = (undefined *)CONCAT44(uStack_5e8._4_4_,iVar12);
        uStack_560 = 0;
        uStack_55c = 0;
        uStack_548 = 7;
        ?SendTraceTag@XlsDiag@@SAXKW4Category@Logging@Mso@@W4Severity@34@W4DataClassifications@34@PE B_WZZ
                  (0x2059f312,0x354,0x32,4);
        ?_Tidy_deallocate@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@AEAAXXZ
                  (&uStack_5e0);
        ?_Tidy_deallocate@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@AEAAXXZ
                  (&uStack_620);
        FUN_1410f8ba0(iStack_700,auStack_318);
      }
      iStack_6fc = iStack_700;
      FUN_1410f8cc0(auStack_108,auStack_318,auStack_1b8);
    }
    if (((*(int *)(*(longlong *)(lVar13 + 0x10) + 0xb9c) == 0) &&
        (*(int *)(*(longlong *)(lVar13 + 0x10) + 0xba8) == 0)) ||
       (_?m_hinstXLIntl@ROGLOBALSCONTAINER@ROGLOBALS@@0PEAUHINSTANCE__@@EA == 0)) {
      ppuStack_720 = (undefined **)CONCAT44(ppuStack_720._4_4_,0x8007);
      ppcStack_728 = (char **)((ulonglong)ppcStack_728 & 0xffffffff00000000);
      _?m_hinstXLIntl@ROGLOBALSCONTAINER@ROGLOBALS@@0PEAUHINSTANCE__@@EA =
           Ordinal_63501(0x110009,&iStack_6fc,2);
      FUN_1406b3550();
      if (_?m_hinstXLIntl@ROGLOBALSCONTAINER@ROGLOBALS@@0PEAUHINSTANCE__@@EA == 0)
      goto LAB_14000ea10;
    }
    if (_?vppxpsa@@3PEAU?$T_MSOPX@PEAUMSOSTARTUPACTION@@@Plex@DoNotUse@Mso@@EA != 0) {
      ?CheckBootActionsEarly@@YAXXZ();
    }
    iVar12 = 0;
    if (*(int *)(*(longlong *)(lVar13 + 0x10) + 0xba8) != 0) {
      pcStack_6f8 = (char *)((ulonglong)pcStack_6f8 & 0xffffffff00000000);
      ppcStack_728 = &pcStack_6f8;
      Ordinal_59604(*(undefined8 *)(*(longlong *)(lVar13 + 0x10) + 0xbb0),auStack_268,0x55,0);
      iVar12 = 0;
      if (-1 < (int)pcStack_6f8) {
        iVar12 = 0x55;
      }
    }
    if (*(int *)(*(longlong *)(lVar13 + 0x10) + 0xb9c) != 0) {
      iVar12 = LCIDToLocaleName(uVar11,auStack_268,0x55,0);
    }
    iStack_700 = 0;
    psStack_6f0 = (short *)((ulonglong)psStack_6f0 & 0xffffffff00000000);
    pcStack_6f8 = (char *)CONCAT44(pcStack_6f8._4_4_,1);
    iVar21 = 0;
    if (*(int *)(*(longlong *)(lVar13 + 0x10) + 0xba8) != 0) {
      FUN_140633b70(&iStack_700,&psStack_6f0,&pcStack_6f8);
      iVar21 = (int)psStack_6f0;
    }
    iVar18 = iStack_700;
    if (iVar12 < 1) {
      cVar4 = Ordinal_39077(auStack_268,0x55);
      if (cVar4 == '\0') goto LAB_14000ea10;
    }
    uStack_530 = 0xffffffff;
    uStack_538 = 0xffffffffffffffff;
    uStack_47e = 0x100;
    uStack_528 = 0;
    uStack_52c = 0;
    uVar16 = ?HcultureFromTag@IntlUtilCache@@QEAAPEAXPEB_W@Z
                       (_?s_spintlutilcache@IntlUtilCache@@0V?$unique_ptr@VIntlUtilCache@@U?$HeapDel eter@VIntlUtilCache@@@@@std@@A
                        ,auStack_268);
    ?InitFromHculture@XLSLOCALEID@@QEAAXPEAX@Z(&uStack_538,uVar16);
    if ((*(int *)(*(longlong *)(lVar13 + 0x10) + 0xb9c) != 0) ||
       (*(int *)(*(longlong *)(lVar13 + 0x10) + 0xba8) != 0)) {
      uVar14 = 1;
    }
    ppcStack_728 = (char **)0x0;
    iVar12 = ?HrInit@LOCALEINFOCACHE@@QEAAJPEAVIMemHeap@@HPEBVXLSLOCALEID@@1@Z
                       (&?m_locinfocache@TSGLOBALSCONTAINER@TSGLOBALS@@0VLOCALEINFOCACHE@@A,
                        &?m_memheapMain@TSGLOBALSCONTAINER@TSGLOBALS@@0VCommonMemoryHeap@@A,uVar 14,
                        &uStack_538);
    if (iVar12 < 0) {
      ?LogFailRetTag@XlsDiag@@SAXJK@Z(iVar12,0x255278a);
      iVar10 = iVar12;
    }
    if (-1 < iVar10) {
      _?WM_AreYouBiDiExcel@@3IA = RegisterWindowMessageA(&??_C@_04HJMNIJDH@RUBE@);
      _?WM_YesIamBiDiExcel@@3IA = RegisterWindowMessageA(&??_C@_04BENCFAAB@YIBE@);
      ?HandleSystemSettingChange@@YAXXZ();
      iVar10 = ?HrInit@APPCORE@@QEAAJXZ();
      if (iVar10 < 0) {
LAB_14000ea1f:
        Ordinal_53798();
        Ordinal_55995();
        Ordinal_50680();
        exit(1);
        pcVar3 = (code *)swi(3);
        (*pcVar3)();
        return;
      }
      iVar10 = ?HrInitMainThread@TLSWIMPL@@QEAAJPEAVIMemHeap@@@Z();
      if (iVar10 < 0) goto LAB_14000ea1f;
      iVar10 = ?FWinInit@@YAHPEA_WPEADH@Z(psStack_6d8,pcStack_6e0,uStack_6e8);
      if (iVar10 == 0) goto LAB_14000ea1f;
      if (cStack_708 != '\0') {
        ?SetSessionFlagToEmbedded@UAEOverride@@SAX_N@Z();
      }
      if (cStack_707 != '\0') {
        ?SetSessionFlagToAutomation@UAEOverride@@SAX_N@Z();
      }
      lVar13 = **(longlong **)(unaff_GS_OFFSET + 0x58);
      if (*(int *)(*(longlong *)(lVar13 + 0x10) + 0x98c) != 0) {
        ?SetSessionFlagToSafeMode@UAEOverride@@SAX_N@Z();
      }
      Ordinal_53798();
      ?InitAutoRecover@@YAXXZ();
      if (*(int *)(*(longlong *)(lVar13 + 0x10) + 0xba8) == 0) {
        FUN_140633b70(&iStack_700,&psStack_6f0,&pcStack_6f8);
        iVar18 = iStack_700;
        iVar21 = (int)psStack_6f0;
      }
      if ((iVar18 != 0) && (iVar21 != 0)) {
        Ordinal_10884();
        Ordinal_48617(iVar18,iVar21,(ulonglong)pcStack_6f8 & 0xffffffff);
        *(undefined4 *)(*(longlong *)(*(longlong *)(lVar13 + 0x10) + 0x548) + 0x1344) = 1;
      }
      if (_?vppxpsa@@3PEAU?$T_MSOPX@PEAUMSOSTARTUPACTION@@@Plex@DoNotUse@Mso@@EA != 0) {
        ?CheckBootActionsLate@@YAXXZ();
      }
      CodeMarker(0x1f5);
      ppcStack_728 = (char **)&
                              ??_C@_1EE@MFHNEAJI@?$AAX?$AAl?$AAM?$AAa?$AAi?$AAn?$AA?3?$AA?5?$AAB?$AA e?$AAf?$AAo?$AAr?$AAe?$AA?5@
      ;
      ?SendTraceTag@XlsDiag@@SAXKW4Category@Logging@Mso@@W4Severity@34@W4DataClassifications@34@PEB_ WZZ
                (0x2059f30c,0x354,0x32);
      ?ConvMainLoop@@YAHXZ();
      Ordinal_13352(auStack_6d0);
      goto LAB_14000e9cb;
    }
    ?DisplayAppNotConfiguredMsg@@YAXXZ();
  }
LAB_14000ea10:
  Ordinal_13352(auStack_6d0);
LAB_14000e9cb:
  __security_check_cookie(uStack_58 ^ (ulonglong)auStack_748);
  return;
}

```





Here is the convmainloop:


```

/* WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void ?ConvMainLoop@@YAHXZ(void)

{
  code *pcVar1;
  char cVar2;
  char cVar3;
  int iVar4;
  int iVar5;
  longlong **pplVar6;
  undefined8 uVar7;
  longlong *plVar8;
  undefined *puVar9;
  longlong lVar10;
  char *pcVar11;
  longlong *plVar12;
  longlong *plVar13;
  longlong *plVar14;
  longlong *plVar15;
  longlong unaff_GS_OFFSET;
  bool bVar16;
  undefined4 uVar17;
  undefined4 extraout_XMM0_Da;
  undefined4 extraout_XMM0_Da_00;
  undefined4 extraout_XMM0_Da_01;
  undefined4 extraout_XMM0_Da_02;
  undefined4 extraout_XMM0_Da_03;
  undefined4 extraout_XMM0_Da_04;
  undefined4 extraout_XMM0_Da_05;
  undefined auStack_ee8 [32];
  char **ppcStack_ec8;
  undefined ***pppuStack_ec0;
  char cStack_eb8;
  char cStack_eb7;
  int iStack_eb4;
  char cStack_eb0;
  int iStack_ea8;
  undefined4 uStack_ea4;
  longlong *plStack_ea0;
  longlong *plStack_e98;
  longlong *plStack_e90;
  char *pcStack_e88;
  longlong *plStack_e80;
  undefined4 uStack_e78;
  undefined uStack_e74;
  undefined4 uStack_e70;
  undefined8 uStack_e68;
  undefined4 uStack_e60;
  undefined4 uStack_e5c;
  undefined8 uStack_e58;
  undefined auStack_e50 [56];
  longlong lStack_e18;
  undefined auStack_e10 [264];
  undefined **ppuStack_d08;
  char *pcStack_d00;
  longlong lStack_cf8;
  undefined2 uStack_cf0;
  undefined8 uStack_ce8;
  undefined8 uStack_ce0;
  undefined8 uStack_cd8;
  undefined8 uStack_cd0;
  undefined8 uStack_cc8;
  undefined8 uStack_cc0;
  undefined8 uStack_cb8;
  undefined8 uStack_cb0;
  undefined auStack_ca8 [32];
  undefined2 auStack_c88 [264];
  undefined4 uStack_a78;
  undefined auStack_a74 [520];
  int iStack_86c;
  undefined2 auStack_868 [257];
  undefined2 uStack_666;
  short asStack_458 [264];
  short asStack_248 [264];
  ulonglong uStack_38;

  uStack_38 = __security_cookie ^ (ulonglong)auStack_ee8;
  plVar14 = (longlong *)0x0;
  iStack_ea8 = 0;
  plStack_e98 = (longlong *)0x0;
  plStack_ea0 = (longlong *)0x0;
  cStack_eb0 = '\0';
  cStack_eb8 = '\0';
  ??0?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAA@QEB_W@Z
            (&uStack_cc8,L"Microsoft.Office.Graphics.Model3D.EngineSupported");
  ??$SetOverride@_N@Test@AB@Mso@@YAXAEBV?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@s td@@AEB_N@Z
            (&uStack_cc8,&cStack_eb8);
  ?_Tidy_deallocate@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@AEAAXXZ
            (&uStack_cc8);
  ?FUninstallBootExceptionHandler@@YAHXZ();
  uVar17 = ?FInstallGeneralExceptionHandler@@YAHXZ();
  cVar2 = ?FConverterSupport@APPCORE@@QEBA_NW4ConverterSupportedFeature@@@Z(uVar17,0x19);
  bVar16 = cVar2 == '\0';
  if (bVar16) {
    pplVar6 = &plStack_e90;
    plStack_e80 = (longlong *)0x0;
  }
  else {
    pplVar6 = (longlong **)
              ?CreateConverterRootActivity@@YA?AV?$unique_ptr@VScopeHolder@ActivityScope@Mso@@U?$def ault_delete@VScopeHolder@ActivityScope@Mso@@@std@@@std@@XZ
                        (&iStack_ea8);
    plStack_e80 = *pplVar6;
  }
  *pplVar6 = (longlong *)0x0;
  plVar13 = plStack_e90;
  if ((bVar16) && (plStack_e90 != (longlong *)0x0)) {
    Ordinal_18876(plStack_e90);
    Ordinal_53248(plVar13);
  }
  if ((!bVar16) && (CONCAT44(uStack_ea4,iStack_ea8) != 0)) {
    ??_GScopeHolder@ActivityScope@Mso@@QEAAPEAXI@Z(CONCAT44(uStack_ea4,iStack_ea8),1);
  }
  if (*(int *)(*(longlong *)(**(longlong **)(unaff_GS_OFFSET + 0x58) + 0x10) + 0x6ec) != 0) {
    iStack_eb4 = 0;
    iStack_ea8 = 0;
    iVar4 = CoInitialize(0);
    if (-1 < iVar4) {
      iVar5 = ?HrRegisterExcelConverterComponent@@YAJPEAPEAVCExcel12Converter@@PEAK@Z
                        (&plStack_e98,&iStack_eb4);
      iVar4 = 0;
      if ((-1 < iVar5) &&
         (iVar5 = ?HrRegisterChartConverterComponent@@YAJPEAPEAVCChart12Converter@@PEAK@Z
                            (&plStack_ea0,&iStack_ea8), plVar14 = plStack_ea0, iVar4 = iStack_ea8 ,
         -1 < iVar5)) {
        iVar5 = GetMessageW(auStack_e50,0,0,0);
        iVar4 = iStack_ea8;
        plVar14 = plStack_ea0;
        while (iStack_ea8 = iVar4, plStack_ea0 = plVar14, iVar5 != 0) {
          if (iVar5 != -1) {
            TranslateMessage(auStack_e50);
            ?DispatchMessageXl@@YA_JPEBUtagMSG@@@Z(auStack_e50);
          }
          iVar5 = GetMessageW(auStack_e50,0,0,0);
          iVar4 = iStack_ea8;
          plVar14 = plStack_ea0;
        }
      }
      if (iStack_eb4 != 0) {
        CoRevokeClassObject();
      }
      if (plStack_e98 != (longlong *)0x0) {
        (**(code **)(*plStack_e98 + 0x10))();
      }
      if (iVar4 != 0) {
        CoRevokeClassObject(iVar4);
      }
      if (plVar14 != (longlong *)0x0) {
        (**(code **)(*plVar14 + 0x10))(plVar14);
      }
    }
    CoUninitialize();
    goto LAB_141af0778;
  }
  cVar2 = ?FConverterSupport@APPCORE@@QEBA_NW4ConverterSupportedFeature@@@Z
                    (**(longlong **)(unaff_GS_OFFSET + 0x58),0x15);
  if (cVar2 == '\0') goto LAB_141af0778;
  cStack_eb8 = '\0';
  plStack_e90 = (longlong *)0x0;
  plStack_e98 = (longlong *)0x0;
  iStack_ea8 = 0;
  cStack_eb7 = '\0';
  uStack_e78 = 1;
  uStack_e74 = 1;
  uStack_e70 = 0;
  uStack_e68 = 0x3ff0000000000000;
  uStack_e60 = 0xffffffff;
  uStack_e5c = 0;
  uStack_e58 = 0;
  memset(asStack_248,0,0x202);
  DAT_14299a808 = 0;
  DAT_14299a810 = 0;
  uVar7 = GetCommandLineW();
  plVar8 = (longlong *)CommandLineToArgvW(uVar7,&iStack_eb4);
  plVar13 = plVar14;
  plStack_ea0 = plVar8;
  if (plVar8 == (longlong *)0x0) {
LAB_141af0122:
    cVar2 = '\0';
    ppcStack_ec8 = (char **)0x142605ae0;
    ?SendTraceTag@XlsDiag@@SAXKW4Category@Logging@Mso@@W4Severity@34@W4DataClassifications@34@PEB_WZ Z
              (0x26c159c,0x354,10);
  }
  else {
    pppuStack_ec0 = (undefined ***)CONCAT44(pppuStack_ec0._4_4_,iStack_eb4);
    ppcStack_ec8 = (char **)0x142605170;
    ?SendTraceTag@XlsDiag@@SAXKW4Category@Logging@Mso@@W4Severity@34@W4DataClassifications@34@PEB_WZ Z
              (0x26c159a,0x354,0x32,4);
    cVar2 = '\x01';
    iVar4 = 1;
    if (iStack_eb4 < 1) goto LAB_141af0122;
    do {
      iVar5 = ?FSzEqual@@YAHPEB_W0@Z(*plVar8,L"-writeSuccessFile");
      if (iVar5 == 0) {
        iVar5 = ?FSzEqual@@YAHPEB_W0@Z(*plVar8,L"-quickExitPostConversion");
        if (iVar5 == 0) {
          iVar5 = ?FSzEqual@@YAHPEB_W0@Z(*plVar8,L"-oice");
          if ((((iVar5 != 0) || (iVar5 = ?FSzEqual@@YAHPEB_W0@Z(*plVar8,L"-oics"), iVar5 != 0)) ||
              (iVar5 = ?FSzEqual@@YAHPEB_W0@Z(*plVar8,L"-bcs"), iVar5 != 0)) &&
             (iVar4 + 1 < iStack_eb4)) {
            plStack_e90 = (longlong *)plVar8[1];
            plVar14 = (longlong *)plVar8[2];
            lVar10 = wcsrchr(plVar14,0x2e);
            if (lVar10 != 0) {
              iVar5 = ?SgnSzCompare@@YA?AW4SGN@@PEB_W0H@Z(lVar10,L".xltx",1);
              if (iVar5 == 0) {
                iStack_ea8 = 4;
              }
              else {
                iVar5 = ?SgnSzCompare@@YA?AW4SGN@@PEB_W0H@Z(lVar10,L".xlam",1);
                if (iVar5 == 0) {
                  iStack_ea8 = 3;
                }
                else {
                  iVar5 = ?SgnSzCompare@@YA?AW4SGN@@PEB_W0H@Z(lVar10,L".xlsm",1);
                  if ((iVar5 == 0) &&
                     (cVar3 = ?FConverterSupport@APPCORE@@QEBA_NW4ConverterSupportedFeature@@@Z
                                        (extraout_XMM0_Da_01,2), cVar3 != '\0')) {
                    iStack_ea8 = 2;
                  }
                  else {
                    iVar5 = ?SgnSzCompare@@YA?AW4SGN@@PEB_W0H@Z(lVar10,L".ods",1);
                    if ((iVar5 == 0) &&
                       (cVar3 = ?FConverterSupport@APPCORE@@QEBA_NW4ConverterSupportedFeature@@@Z
                                          (extraout_XMM0_Da_02,0xf), cVar3 != '\0')) {
                      iStack_ea8 = 8;
                      ?s_fConvertingToODF@ConverterContext@@0HA = 1;
                    }
                    else {
                      iVar5 = ?SgnSzCompare@@YA?AW4SGN@@PEB_W0H@Z(lVar10,L".csv",1);
                      if ((iVar5 == 0) &&
                         (cVar3 = ?FConverterSupport@APPCORE@@QEBA_NW4ConverterSupportedFeature@@@Z
                                            (extraout_XMM0_Da_03,0x14), cVar3 != '\0')) {
                        iStack_ea8 = 9;
                        ?s_fConvertingToCSV@ConverterContext@@0_NA = '\x01';
                      }
                      else {
                        iVar5 = ?SgnSzCompare@@YA?AW4SGN@@PEB_W0H@Z(lVar10,L".xls*",1);
                        if ((iVar5 == 0) &&
                           (cVar3 = ?FConverterSupport@APPCORE@@QEBA_NW4ConverterSupportedFeature@@ @Z
                                              (extraout_XMM0_Da_04,2), cVar3 != '\0')) {
                          ?s_fDynamicConversion@ConverterContext@@0HA = 1;
                        }
                        else {
                          iVar5 = ?SgnSzCompare@@YA?AW4SGN@@PEB_W0H@Z(lVar10,L".pdf",1);
                          if ((iVar5 == 0) &&
                             (cVar3 = ?FConverterSupport@APPCORE@@QEBA_NW4ConverterSupportedFeature @@@Z
                                                (extraout_XMM0_Da_05,6), cVar3 != '\0')) {
                            puVar9 = (undefined *)
                                     ?PConvPrintSettings@ConverterContext@@SAPEAVConverterPrintSetti ngs@@XZ
                                               ();
                            ppcStack_ec8 = (char **)0x142442a80;
                            ?SendTraceTag@XlsDiag@@SAXKW4Category@Logging@Mso@@W4Severity@34@W4DataC lassifications@34@PEB_WZZ
                                      (0x650753,0x354,0x32);
                            ?InitDefaultPaperSize@ConverterPrintSettings@@AEAAXXZ(puVar9);
                            *puVar9 = 1;
                            iStack_ea8 = 7;
                          }
                          else {
                            iVar5 = ?SgnSzCompare@@YA?AW4SGN@@PEB_W0H@Z(lVar10,L".xlsx",1);
                            if (iVar5 == 0) {
                              ?s_fStripVBAProject@ConverterContext@@0HA =
                                   ?FSzEqual@@YAHPEB_W0@Z(*plVar8,L"-oics");
                            }
                            else {
                              iVar5 = ?SgnSzCompare@@YA?AW4SGN@@PEB_W0H@Z(lVar10,L".png",1);
                              if (iVar5 == 0) {
                                uStack_e74 = 1;
                                ?s_fGeneratingThumbnail@ConverterContext@@0_NA = '\x01';
                              }
                              else {
                                iVar5 = ?SgnSzCompare@@YA?AW4SGN@@PEB_W0H@Z(lVar10,L".jpg",1);
                                if (iVar5 == 0) {
                                  uStack_e74 = 0;
                                  ?s_fGeneratingThumbnail@ConverterContext@@0_NA = '\x01';
                                }
                                else {
                                  ppuStack_d08 = &
                                                 ??_7?$ClassifiedStructuredObject@PEB_W@Diagnostics@ Mso@@6B@
                                  ;
                                  pcStack_d00 = "Input file extension";
                                  uStack_cf0 = 0x20;
                                  uStack_ce0 = 0;
                                  uStack_cd8 = 0;
                                  uStack_cd0 = 7;
                                  uStack_ce8 = 0;
                                  pcStack_e88 =
                                  "Unknown output extension passed to converter, defaulting to xlsx! "
                                  ;
                                  pppuStack_ec0 = &ppuStack_d08;
                                  ppcStack_ec8 = &pcStack_e88;
                                  lStack_cf8 = lVar10;
                                  ??$SendDiagnosticTrace@U?$ClassifiedStructuredObject@PEB_W@Diagnos tics@Mso@@@Diagnostics@Mso@@YAXKW4Category@Logging@1@W4Severity@31 @W4ValidDataCategories@01@AEBV?$StringLiteral@D@StringLiterals@1@$ $QEAU?$ClassifiedStructuredObject@PEB_W@01@@Z
                                            (0x64e405,0x354,10);
                                  ?_Tidy_deallocate@?$basic_string@_WU?$char_traits@_W@std@@V?$alloc ator@_W@2@@std@@AEAAXXZ
                                            (&uStack_ce8);
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
          pcVar11 = (char *)?PConvPrintSettings@ConverterContext@@SAPEAVConverterPrintSettings@@XZ ()
          ;
          if (*pcVar11 != '\0') {
            uVar7 = ?PConvPrintSettings@ConverterContext@@SAPEAVConverterPrintSettings@@XZ();
            cVar2 = ?FParseFromCmdLineArgs@ConverterPrintSettings@@QEAA_NPEAPEA_WH@Z
                              (uVar7,plStack_ea0,iStack_eb4);
          }
          iVar5 = ?FSzEqual@@YAHPEB_W0@Z(*plVar8,L"-repair");
          if (iVar5 != 0) {
            DAT_1429c30f8 = '\x01';
            if (iStack_eb4 <= iVar4) {
              cVar2 = '\0';
              ppcStack_ec8 = (char **)0x142605930;
              ?SendTraceTag@XlsDiag@@SAXKW4Category@Logging@Mso@@W4Severity@34@W4DataClassifications @34@PEB_WZZ
                        (0x26c159b,0x354,10);
              break;
            }
            plStack_e98 = (longlong *)plVar8[1];
          }
          iVar5 = ?FSzEqual@@YAHPEB_W0@Z(*plVar8,&??_C@_15BJCIDILG@?$AA?9?$AAk@);
          uVar17 = extraout_XMM0_Da;
          if ((((iVar5 != 0) && (iVar4 < iStack_eb4)) &&
              (iVar5 = ?OpenAndReadKey@@YAHPEB_W@Z(plVar8[1]), uVar17 = extraout_XMM0_Da_00,
              iVar5 == 0)) ||
             (((cVar3 = ?FConverterSupport@APPCORE@@QEBA_NW4ConverterSupportedFeature@@@Z
                                  (uVar17,0x12), cVar3 != '\0' &&
               (iVar5 = ?FSzEqual@@YAHPEB_W0@Z(*plVar8,L"-passwordnamedpipeid"), iVar5 != 0)) &&
              ((iVar4 < iStack_eb4 &&
               (iVar5 = ?OpenPipeAndReadPassword@@YAHPEB_WPEA_W@Z(plVar8[1],asStack_248), iVar5 == 0
               )))))) {
            cVar2 = '\0';
            break;
          }
          iVar5 = ?FSzEqual@@YAHPEB_W0@Z(*plVar8,L"-flightodfrepairenabled");
          if (iVar5 != 0) {
            ?s_fConverterOdfFileRepairEnabled@ConverterContext@@0_NA = 1;
          }
          iVar5 = ?FSzEqual@@YAHPEB_W0@Z(*plVar8,L"-mdp");
          if ((iVar5 != 0) && (iVar4 < iStack_eb4)) {
            ?s_wzPathToWriteMetadataFile@ConverterContext@@0PEA_WEA = plVar8[1];
            ?s_fWriteMetadataFile@ConverterContext@@0_NA = '\x01';
          }
          iVar5 = ?FSzEqual@@YAHPEB_W0@Z(*plVar8,L"-keepPDFProtection");
          if (iVar5 != 0) {
            ?s_fKeepPDFProtection@ConverterContext@@0_NA = 1;
          }
          iVar5 = ?FSzEqual@@YAHPEB_W0@Z(*plVar8,L"-clpTenantId");
          if ((iVar5 != 0) && (iVar4 < iStack_eb4)) {
            ?s_wzTenantId@ConverterContext@@0PEA_WEA = plVar8[1];
          }
          iVar5 = ?FSzEqual@@YAHPEB_W0@Z(*plVar8,L"-clpSupportsOfficeClientCoauthoring");
          if (iVar5 != 0) {
            ?s_fSupportsOfficeClientCoauthoring@ConverterContext@@0_NA = 1;
          }
          iVar5 = ?FSzEqual@@YAHPEB_W0@Z(*plVar8,L"-allowMismatchedFileFormatConversionForBCS");
          if (iVar5 != 0) {
            ?s_fAllowMismatchedFileFormatConversionForBCS@ConverterContext@@0_NA = 1;
          }
        }
        else {
          ppcStack_ec8 = (char **)0x1426052e0;
          ?SendTraceTag@XlsDiag@@SAXKW4Category@Logging@Mso@@W4Severity@34@W4DataClassifications@34@ PEB_WZZ
                    (0x1e623149,0x354,0x32);
          cStack_eb8 = '\x01';
        }
      }
      else {
        ppcStack_ec8 = (char **)0x142605250;
        ?SendTraceTag@XlsDiag@@SAXKW4Category@Logging@Mso@@W4Severity@34@W4DataClassifications@34@PE B_WZZ
                  (0x1e61735e,0x354,0x32);
        cStack_eb0 = '\x01';
      }
      plVar8 = plVar8 + 1;
      bVar16 = iVar4 < iStack_eb4;
      iVar4 = iVar4 + 1;
    } while (bVar16);
    plVar13 = plStack_e90;
    if (((plStack_e90 == (longlong *)0x0) || (plVar14 == (longlong *)0x0)) ||
       ((DAT_1429c30f8 != '\0' && (plStack_e98 == (longlong *)0x0)))) goto LAB_141af0122;
  }
  plVar8 = plStack_ea0;
  if (?s_fGeneratingThumbnail@ConverterContext@@0_NA != '\0') {
    cVar2 = ?FParseCmdLineArgsThumbnail@@YA_NPEAPEA_WHPEAUThumbnailParams@@@Z
                      (plStack_ea0,iStack_eb4,&uStack_e78);
  }
  cVar3 = cStack_eb7;
  if (((plVar13 != (longlong *)0x0) &&
      (lVar10 = wcsrchr(plVar13,0x2e), cVar3 = cStack_eb7, lVar10 != 0)) &&
     ((iVar4 = Ordinal_55665(lVar10,L".csv",1), iVar4 != 0 ||
      (iVar4 = Ordinal_55665(lVar10,L".skv",1), cVar3 = cStack_eb7, iVar4 != 0)))) {
    cVar3 = '\x01';
  }
  lVar10 = **(longlong **)(unaff_GS_OFFSET + 0x58);
  if ((((*(int *)(*(longlong *)(lVar10 + 0x10) + 0xb9c) != 0) &&
       (pcVar11 = (char *)?PConvPrintSettings@ConverterContext@@SAPEAVConverterPrintSettings@@XZ (),
       *pcVar11 == '\0')) && (cVar3 == '\0')) &&
     ((DAT_1429c30f8 == '\0' && (?s_fConvertingToCSV@ConverterContext@@0_NA == '\0')))) {
    ppcStack_ec8 = (char **)0x142605480;
    ?SendTraceTag@XlsDiag@@SAXKW4Category@Logging@Mso@@W4Severity@34@W4DataClassifications@34@PEB_WZ Z
              (0x64e406,0x354,10,4);
    cVar2 = '\0';
  }
  if ((*(int *)(*(longlong *)(lVar10 + 0x10) + 0xba8) != 0) &&
     (pcVar11 = (char *)?PConvPrintSettings@ConverterContext@@SAPEAVConverterPrintSettings@@XZ() ,
     *pcVar11 == '\0')) {
    ppcStack_ec8 = (char **)0x1426053f0;
    ?SendTraceTag@XlsDiag@@SAXKW4Category@Logging@Mso@@W4Severity@34@W4DataClassifications@34@PEB_WZ Z
              (0x2169b596,0x354,10,4);
    cVar2 = '\0';
  }
  if (cVar2 == '\0') {
    lStack_cf8 = GetCommandLineW();
    ppuStack_d08 = &??_7?$ClassifiedStructuredObject@PEB_W@Diagnostics@Mso@@6B@;
    pcStack_d00 = "Command line arguments";
    uStack_cf0 = 0x20;
    uStack_ce0 = 0;
    uStack_cd8 = 0;
    uStack_cd0 = 7;
    uStack_ce8 = 0;
    pcStack_e88 = "Invalid command line arguments passed to converter";
    pppuStack_ec0 = &ppuStack_d08;
    ppcStack_ec8 = &pcStack_e88;
    ??$SendDiagnosticTrace@U?$ClassifiedStructuredObject@PEB_W@Diagnostics@Mso@@@Diagnostics@Mso@@YA XKW4Category@Logging@1@W4Severity@31@W4ValidDataCategories@01@AEBV?$StringLiteral@D@StringLitera ls@1@$$QEAU?$ClassifiedStructuredObject@PEB_W@01@@Z
              (0x64e409,0x354,10);
    ?_Tidy_deallocate@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@AEAAXXZ
              (&uStack_ce8);
    _?s_scfcConversionError@ConverterContext@@0HA = 0x100000;
  }
  else {
    pcVar11 = (char *)?PConvPrintSettings@ConverterContext@@SAPEAVConverterPrintSettings@@XZ();
    plVar13 = (longlong *)0x0;
    if (*pcVar11 != '\0') {
      ?EnumFaceNames@@YAXPEB_WPEAUFLST@@HH@Z(0,0,4);
    }
    asStack_458[0] = 0;
    if (0 < iStack_eb4) {
      ?AddOfficeSymbolFont@@YAXPEB_WPEA_WH@Z(*plVar8,asStack_458);
    }
    uStack_a78 = 0;
    if (asStack_248[0] == 0) {
      auStack_868[0] = 0;
    }
    else {
      ?CchSzToSt@@YAHPEB_WPEA_WH@Z(asStack_248,auStack_868,0x101);
    }
    uStack_666 = 0;
    iStack_86c = iStack_ea8;
    auStack_c88[0] = 0;
    ?MsoWzCopy@@YAPEA_WPEB_WPEA_WH@Z(plStack_e90,auStack_a74,0x104);
    plVar12 = (longlong *)??2@YAPEAX_KAEBUnothrow_t@std@@@Z(0x38);
    plVar15 = plVar13;
    if (plVar12 != (longlong *)0x0) {
      *plVar12 = (longlong)&??_7CExcel12Converter@@6BIExcel12Converter@@@;
      plVar12[1] = (longlong)&??_7CExcel12Converter@@6BIClassFactory@@@;
      plVar12[5] = 0;
      plVar12[6] = 0;
      plVar12[2] = 0;
      plVar12[4] = 0;
      plVar15 = plVar12;
    }
    if (plVar15 != (longlong *)0x0) {
      iVar4 = (**(code **)(*plVar15 + 0x18))(plVar15,0);
      if (-1 < iVar4) {
        ppcStack_ec8 = (char **)0x142605620;
        ?SendTraceTag@XlsDiag@@SAXKW4Category@Logging@Mso@@W4Severity@34@W4DataClassifications@34@PE B_WZZ
                  (0x64e407,0x354,0x32);
        if (?s_fGeneratingThumbnail@ConverterContext@@0_NA != '\0') {
          plVar15[5] = (longlong)&uStack_e78;
        }
        cVar2 = ?FForceInCellControlsPrintingInConverter@InCellControlsFlighting@@SA_NXZ();
        if (cVar2 != '\0') {
          plVar15[6] = (longlong)asStack_458;
        }
        iVar4 = (**(code **)(*plVar15 + 0x28))(plVar15,&uStack_a78,auStack_c88);
        uVar17 = (**(code **)(*plVar15 + 0x30))(plVar15);
        if (-1 < iVar4) {
          cVar2 = ?FConverterSupport@APPCORE@@QEBA_NW4ConverterSupportedFeature@@@Z(uVar17,3);
          if (cVar2 != '\0') {
            if (?s_fDynamicallyConvertedToXlsm@ConverterContext@@0HA == 0) {
              plVar12 = (longlong *)0xffffffffffffffff;
              if (plVar14 != (longlong *)0x0) {
                do {
                  plVar13 = (longlong *)((longlong)plVar12 + 1);
                  plVar12 = plVar13;
                } while (*(short *)((longlong)plVar14 + (longlong)plVar13 * 2) != 0);
              }
              *(undefined2 *)((longlong)plVar14 + (longlong)(int)plVar13 * 2 + -2) = 0x78;
            }
            else {
              plVar12 = (longlong *)0xffffffffffffffff;
              if (plVar14 != (longlong *)0x0) {
                do {
                  plVar13 = (longlong *)((longlong)plVar12 + 1);
                  plVar12 = plVar13;
                } while (*(short *)((longlong)plVar14 + (longlong)plVar13 * 2) != 0);
              }
              *(undefined2 *)((longlong)plVar14 + (longlong)(int)plVar13 * 2 + -2) = 0x6d;
              ppcStack_ec8 = (char **)0x142605540;
              ?SendTraceTag@XlsDiag@@SAXKW4Category@Logging@Mso@@W4Severity@34@W4DataClassifications @34@PEB_WZZ
                        (0x65d321,0x354,0x32,4);
              _?s_scfcConversionError@ConverterContext@@0HA = 0xc0000;
            }
          }
          ppcStack_ec8 = (char **)0x1426056f0;
          ?SendTraceTag@XlsDiag@@SAXKW4Category@Logging@Mso@@W4Severity@34@W4DataClassifications@34@ PEB_WZZ
                    (0x1e3d60db,0x354,0x32,4);
          uVar17 = CopyFileW(auStack_c88,plVar14,0);
          if (DAT_1429c30fa != 0) {
            uVar17 = CopyFileW(&DAT_1429c30fa,plStack_e98,0);
          }
          cVar2 = ?FConverterSupport@APPCORE@@QEBA_NW4ConverterSupportedFeature@@@Z(uVar17,0x1a) ;
          if ((cVar2 != '\0') && (?s_fWriteMetadataFile@ConverterContext@@0_NA != '\0')) {
            ?WriteMetadataFile@ConverterContext@@SAXXZ();
          }
          ppcStack_ec8 = (char **)0x142605690;
          ?SendTraceTag@XlsDiag@@SAXKW4Category@Logging@Mso@@W4Severity@34@W4DataClassifications@34@ PEB_WZZ
                    (0x64e408,0x354,0x32,4);
          if (cStack_eb0 != '\0') {
            uStack_cc0 = 0;
            uStack_cb8 = 0;
            uStack_cb0 = 7;
            uStack_cc8 = 0;
            uVar7 = ??0?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAA@QEB_W@Z
                              (&ppuStack_d08,L".tmp");
            uVar7 = ??$?H_WU?$char_traits@_W@std@@V?$allocator@_W@1@@std@@YA?AV?$basic_string@_WU?$ char_traits@_W@std@@V?$allocator@_W@2@@0@QEB_W$$QEAV10@@Z
                              (auStack_ca8,plVar14,uVar7);
            ??4?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@$$QEAV01@@ Z
                      (&uStack_cc8,uVar7);
            ?_Tidy_deallocate@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@AEAAXX Z
                      (auStack_ca8);
            ?_Tidy_deallocate@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@AEAAXX Z
                      (&ppuStack_d08);
            ??0?$basic_ofstream@DU?$char_traits@D@std@@@std@@QEAA@AEBV?$basic_string@_WU?$char_trait s@_W@std@@V?$allocator@_W@2@@1@HH@Z
                      (&lStack_e18,&uStack_cc8);
            ??$?6U?$char_traits@D@std@@@std@@YAAEAV?$basic_ostream@DU?$char_traits@D@std@@@0@AEAV10@ PEBD@Z
                      (&lStack_e18,"Temp file created for successful conversions.");
            lVar10 = ?close@?$basic_filebuf@DU?$char_traits@D@std@@@std@@QEAAPEAV12@XZ(auStack_e 10);
            if (lVar10 == 0) {
              ?setstate@?$basic_ios@DU?$char_traits@D@std@@@std@@QEAAXH_N@Z
                        (auStack_e10 + (longlong)*(int *)(lStack_e18 + 4) + -8,2);
            }
            ??_D?$basic_ofstream@DU?$char_traits@D@std@@@std@@QEAAXXZ(&lStack_e18);
            ?_Tidy_deallocate@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@AEAAXX Z
                      (&uStack_cc8);
          }
        }
      }
      if (cStack_eb8 != '\0') {
        ppcStack_ec8 = (char **)0x1426057d0;
        ?SendTraceTag@XlsDiag@@SAXKW4Category@Logging@Mso@@W4Severity@34@W4DataClassifications@34@PE B_WZZ
                  (0x1e623148,0x354,0x32,4);
        uVar17 = _?s_scfcConversionError@ConverterContext@@0HA;
        uVar7 = GetCurrentProcess();
        TerminateProcess(uVar7,uVar17);
      }
      Ordinal_53248(plVar15);
    }
    if ((asStack_458[0] != 0) && (iVar4 = RemoveFontResourceExW(asStack_458,0x10), iVar4 == 0)) {
      ppcStack_ec8 = (char **)0x142605760;
      ?SendTraceTag@XlsDiag@@SAXKW4Category@Logging@Mso@@W4Severity@34@W4DataClassifications@34@PEB_ WZZ
                (0x258e8e0,0x354,10);
    }
  }
  if (plVar8 != (longlong *)0x0) {
    LocalFree(plVar8);
  }
  if (DAT_14299a808 != 0) {
    Ordinal_53248();
  }
LAB_141af0778:
  if (plStack_e80 != (longlong *)0x0) {
    ??_GScopeHolder@ActivityScope@Mso@@QEAAPEAXI@Z(plStack_e80,1);
  }
  iStack_ea8 = 0;
  iVar4 = ?HrDoQuit@@YAJPEAPEAUOPER@@HHPEAH@Z(0,0,0,&iStack_ea8);
  if (-1 < iVar4) {
    __security_check_cookie(uStack_38 ^ (ulonglong)auStack_ee8);
    return;
  }
  ?CrashOrDoJmpHr@@YAXW4DoJmpRemovalMonth@@PEAUENV@@JI@Z
            (1,*(undefined8 *)
                (*(longlong *)(**(longlong **)(unaff_GS_OFFSET + 0x58) + 0x10) + 0x150),iVar4,
             0x1f107701);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



```




















Here is the chatgpt summary of this:

```

Absolutely — that’s a very good reverse-engineering exercise!
Let’s walk through it step-by-step — I'll give you a clear, structured breakdown of what this ConvMainLoop() is doing based on your decompiled C++ code.

🛠 High-Level Structure of ConvMainLoop()
(what it roughly does)


Phase	What Happens
1. Security setup	Calls __security_cookie functions, basic anti-stack smashing stuff
2. Initialization	Installs exception handlers, maybe logging setup
3. Check environment	Sees if Excel conversion features are supported
4. COM Initialization	Calls CoInitialize() for COM object management
5. Component Registration	Registers Excel and Chart converter components
6. Windows Message Loop	Waits for incoming Windows messages while converting
7. Command Line Parsing	Parses command line arguments for conversion settings
8. Error Handling	Sends diagnostics if invalid command line args
9. Converter Object Creation	Instantiates converter classes dynamically
10. Perform Conversion	Actually processes the file and does conversion
11. Cleanup	Frees memory, releases COM objects, uninstalls handlers
🔍 Step-by-Step Details
1. Security
c
Kopioi
Muokkaa
uStack_38 = __security_cookie ^ (ulonglong)auStack_ee8;
Typical for compiled Windows binaries to initialize a security cookie to prevent buffer overflow attacks.

2. Install Exception Handlers
c
Kopioi
Muokkaa
?FInstallGeneralExceptionHandler@@YAHXZ();
It installs custom crash handlers for debugging crashes during conversion.

3. Check for Feature Support
c
Kopioi
Muokkaa
?FConverterSupport@APPCORE@@QEBA_NW4ConverterSupportedFeature@@@Z(uVar17, 0x19);
It checks whether a certain "conversion feature" (ID 0x19) is supported. If not, it initializes a "dummy" environment.

4. COM Initialization
c
Kopioi
Muokkaa
CoInitialize(0);
Excel converters use COM (Component Object Model), so it sets up COM.

5. Register Converter Components
c
Kopioi
Muokkaa
?HrRegisterExcelConverterComponent@@(...);
?HrRegisterChartConverterComponent@@(...);
Registers Excel and Chart converter components into the COM system.

6. Message Loop
c
Kopioi
Muokkaa
while (GetMessageW(auStack_e50,0,0,0) != 0) {
    TranslateMessage(auStack_e50);
    ?DispatchMessageXl@@YA_JPEBUtagMSG@@@Z(auStack_e50);
}
Classic Windows message loop! It:

Receives Windows events (keyboard, window close, etc.)

Translates them

Dispatches them to handlers

This keeps the converter alive while it works or waits.

7. Command Line Argument Parsing
c
Kopioi
Muokkaa
CommandLineToArgvW(...)
It parses the command line for:

Source file

Target file

Options like:

-writeSuccess

-quickExit

-office

-csv

-odf

etc.

It determines what file to convert and how based on command-line switches!

8. Error Handling for Bad Input
c
Kopioi
Muokkaa
?SendTraceTag@XlsDiag@@(...);
If the arguments are wrong, it sends diagnostic error reports and terminates early.

9. Converter Object Creation
c
Kopioi
Muokkaa
plVar12 = (longlong *)??2@YAPEAX_KAEBUnothrow_t@std@@@Z(0x38);
It allocates memory.

Creates a converter object (likely a CExcel12Converter).

Sets up pointers to virtual tables (vtables) for Excel or Chart conversion classes.

10. Performing the Conversion
Calls into the converter object to open the input file.

Maybe modifies it.

Writes the output to a file.

May generate a thumbnail or strip macros based on options.

In some cases, metadata files are written too.

11. Cleanup
c
Kopioi
Muokkaa
CoUninitialize();
LocalFree(plVar8);
Ordinal_53248();
Uninitializes COM

Frees memory

Destroys internal states and allocated structures

May terminate the process with error codes if fatal errors happen

🧠 Summary: How it Works
Sets up error handlers

Initializes Windows COM

Parses command line to figure out what file to convert and how

Registers Excel converters

Enters a Windows Message Loop while the conversion happens

If needed, opens files, processes them, saves the result

Cleans up everything safely when done

⚡️ Extra Observations
Command-line control: You can trigger CSV, XLSX, XLSM, or ODF outputs depending on the file extension.

Dynamic behavior: Some converter options seem enabled/disabled based on runtime feature flags.

Internal crash reporting: There's heavy use of "TraceTag" for internal Microsoft logging if things go wrong.

Would you like me to also draw a simple flowchart diagram showing this visually? 📈 It could help you understand it even faster!
(And maybe I can guess where you'd hook into it if you wanted to modify or fuzz it too.) 🎯







Sinä sanoit:
Which lines do the actual conversion?


ChatGPT sanoi:
Good focus — let’s zoom in sharply on your question:
Where in ConvMainLoop() does the actual conversion happen?

🧠 Quick answer:
The actual conversion happens through the virtual function calls on the converter object (plVar15).

Specifically:

🟰 Critical lines
c
Kopioi
Muokkaa
iVar4 = (**(code **)(*plVar15 + 0x28))(plVar15, &uStack_a78, auStack_c88);
uVar17 = (**(code **)(*plVar15 + 0x30))(plVar15);
First line (+0x28 function pointer):
→ Probably runs the conversion itself — from source file to output file.

Second line (+0x30 function pointer):
→ Maybe finalizes or saves the conversion output.

🔬 Why?
plVar15 points to a CExcel12Converter-like object (or chart converter).

*(code **)(*plVar15 + offset) accesses its vtable (virtual function table).

Calling offset 0x28 and offset 0x30 are method calls on the converter, which is typical object-oriented compiled C++.

Usually, you'd see this pattern:


VTable Offset	Function purpose (guess)
0x18	Initialization (seen earlier)
0x28	Main conversion (transform input into desired output)
0x30	Finalize or save (e.g., write to disk)
🧹 Context
Earlier setup (CommandLineToArgvW, etc.) just prepares filenames and parameters.
Only after the converter object (plVar15) is properly created and initialized does it actually perform conversion here.

Then after the conversion:

It handles copy file operations (maybe for temporary files).

It writes metadata files if necessary.

It cleans up the converter object.

🎯 Short and sharp:
✅ Actual conversion starts at this virtual method call:

c
Kopioi
Muokkaa
(**(code **)(*plVar15 + 0x28))(plVar15, &uStack_a78, auStack_c88);
and is completed (or post-processed) by:

c
Kopioi
Muokkaa
(**(code **)(*plVar15 + 0x30))(plVar15);
Would you also want me to guess what the function signatures look like at 0x28 and 0x30? (like how many arguments, what they are)
It would be useful if you're trying to intercept, hook, or fuzz this! 🎯👾
Let me know!

```


Here are the two calls:

```
                             LAB_141af03c7                                   XREF[1]:     141af03ba (j)
       141af03c7 48  8b  07       MOV        RAX ,qword ptr [RDI ]
       141af03ca 4c  8d  85       LEA        R8 ,[RBP  + 0x160 ]
                 60  01  00
                 00
       141af03d1 48  8d  95       LEA        RDX ,[RBP  + 0x370 ]
                 70  03  00
                 00
       141af03d8 48  8b  cf       MOV        RCX ,RDI
       141af03db 48  8b  40       MOV        RAX ,qword ptr [RAX  + 0x28 ]=> -> CExcel12Converte  = 14010fa30
                 28
       141af03df ff  15  6b       CALL       qword ptr [-> _guard_dispatch_icall ]            long HrConvertUp(CExcel12Convert
                 ac  81  00                                                                   undefined _guard_dispatch_icall(
                                                                                             = 1422ddf80
       141af03e5 8b  d8           MOV        EBX ,EAX
       141af03e7 48  8b  0f       MOV        RCX ,qword ptr [RDI ]
       141af03ea 48  8b  41       MOV        RAX ,qword ptr [RCX  + 0x30 ]=> -> CExcel12Converte  = 1400279f0
                 30
       141af03ee 48  8b  cf       MOV        RCX ,RDI
       141af03f1 ff  15  59       CALL       qword ptr [-> _guard_dispatch_icall ]            long HrAfterFileConvert(CExcel12
                 ac  81  00                                                                   undefined _guard_dispatch_icall(
                                                                                             = 1422ddf80
       141af03f7 85  db           TEST       EBX ,EBX
       141af03f9 0f  88  03       JS         LAB_141af0602
                 02  00  00

```




Here is the final decompiled function:

```

/* WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall */
/* int __cdecl ConvMainLoop(void) */

int __cdecl ConvMainLoop(void)

{
  code *pcVar1;
  bool bVar2;
  bool bVar3;
  int iVar4;
  long lVar5;
  int iVar6;
  SGN SVar7;
  int iVar8;
  CChart12Converter **ppCVar9;
  undefined8 uVar10;
  CChart12Converter *pCVar11;
  longlong lVar12;
  ConverterPrintSettings *pCVar13;
  APPCORE *pAVar14;
  basic_string<> *pbVar15;
  basic_filebuf<> *pbVar16;
  APPCORE *pAVar17;
  short *this;
  nothrow_t *pnVar18;
  ulong uVar19;
  CChart12Converter *pCVar20;
  APPCORE *pAVar21;
  char cVar22;
  CChart12Converter *pCVar23;
  ulonglong uVar24;
  ThumbnailParams *pTVar25;
  ValidDataCategories VVar26;
  longlong unaff_GS_OFFSET;
  undefined auStackY_ee8 [32];
  bool bStack_eb8;
  char cStack_eb7;
  ulong uStack_eb4;
  char cStack_eb0;
  ulong uStack_ea8;
  undefined4 uStack_ea4;
  CChart12Converter *pCStack_ea0;
  CExcel12Converter *pCStack_e98;
  CChart12Converter *pCStack_e90;
  char *pcStack_e88;
  CChart12Converter *pCStack_e80;
  undefined4 uStack_e78;
  undefined uStack_e74;
  undefined4 uStack_e70;
  undefined8 uStack_e68;
  undefined4 uStack_e60;
  undefined4 uStack_e5c;
  undefined8 uStack_e58;
  tagMSG atStack_e50 [56];
  longlong lStack_e18;
  basic_filebuf<> abStack_e10 [264];
  undefined **ppuStack_d08;
  char *pcStack_d00;
  APPCORE *pAStack_cf8;
  undefined2 uStack_cf0;
  undefined8 uStack_ce8;
  undefined8 uStack_ce0;
  undefined8 uStack_cd8;
  undefined8 uStack_cd0;
  undefined8 uStack_cc8;
  undefined8 uStack_cc0;
  undefined8 uStack_cb8;
  undefined8 uStack_cb0;
  basic_string<> abStack_ca8 [32];
  undefined2 auStack_c88 [264];
  undefined4 uStack_a78;
  nothrow_t anStack_a74 [520];
  ulong uStack_86c;
  wchar_t awStack_868 [257];
  undefined2 uStack_666;
  wchar_t awStack_458 [264];
  wchar_t awStack_248 [264];
  ulonglong uStack_38;

  uStack_38 = __security_cookie ^ (ulonglong)auStackY_ee8;
  pCVar23 = (CChart12Converter *)0x0;
  uStack_ea8 = 0;
  pCStack_e98 = (CExcel12Converter *)0x0;
  pCStack_ea0 = (CChart12Converter *)0x0;
  cStack_eb0 = '\0';
  bStack_eb8 = false;
  std::basic_string<>::basic_string<>
            ((basic_string<> *)&uStack_cc8,L"Microsoft.Office.Graphics.Model3D.EngineSupported") ;
  Mso::AB::Test::SetOverride<bool>((basic_string<> *)&uStack_cc8,&bStack_eb8);
  pbVar15 = (basic_string<> *)&uStack_cc8;
  std::basic_string<>::_Tidy_deallocate(pbVar15);
  FUninstallBootExceptionHandler();
  FInstallGeneralExceptionHandler();
  bVar2 = APPCORE::FConverterSupport((APPCORE *)pbVar15,0x19);
  bVar2 = !bVar2;
  if (bVar2) {
    ppCVar9 = &pCStack_e90;
    pCStack_e80 = (CChart12Converter *)0x0;
  }
  else {
    ppCVar9 = (CChart12Converter **)CreateConverterRootActivity(&uStack_ea8);
    pCStack_e80 = *ppCVar9;
  }
  *ppCVar9 = (CChart12Converter *)0x0;
  pCVar20 = pCStack_e90;
  if ((bVar2) && (pCStack_e90 != (CChart12Converter *)0x0)) {
    Ordinal_18876(pCStack_e90);
    Ordinal_53248(pCVar20);
  }
  if ((!bVar2) && ((ScopeHolder *)CONCAT44(uStack_ea4,uStack_ea8) != (ScopeHolder *)0x0)) {
    Mso::ActivityScope::ScopeHolder::`scalar_deleting_destructor'
              ((ScopeHolder *)CONCAT44(uStack_ea4,uStack_ea8),1);
  }
  if (*(int *)(*(longlong *)((APPCORE *)**(undefined8 **)(unaff_GS_OFFSET + 0x58) + 0x10) + 0x6ec )
      != 0) {
    uStack_eb4 = 0;
    uStack_ea8 = 0;
    iVar4 = CoInitialize();
    if (-1 < iVar4) {
      lVar5 = HrRegisterExcelConverterComponent(&pCStack_e98,&uStack_eb4);
      uVar19 = 0;
      if ((-1 < lVar5) &&
         (lVar5 = HrRegisterChartConverterComponent(&pCStack_ea0,&uStack_ea8), pCVar23 = pCStack _ea0
         , uVar19 = uStack_ea8, -1 < lVar5)) {
        iVar4 = GetMessageW(atStack_e50,0,0,0);
        uVar19 = uStack_ea8;
        pCVar23 = pCStack_ea0;
        while (uStack_ea8 = uVar19, pCStack_ea0 = pCVar23, iVar4 != 0) {
          if (iVar4 != -1) {
            TranslateMessage(atStack_e50);
            DispatchMessageXl(atStack_e50);
          }
          iVar4 = GetMessageW(atStack_e50,0,0,0);
          uVar19 = uStack_ea8;
          pCVar23 = pCStack_ea0;
        }
      }
      if (uStack_eb4 != 0) {
        CoRevokeClassObject();
      }
      if (pCStack_e98 != (CExcel12Converter *)0x0) {
        (**(code **)(*(longlong *)pCStack_e98 + 0x10))();
      }
      if (uVar19 != 0) {
        CoRevokeClassObject();
      }
      if (pCVar23 != (CChart12Converter *)0x0) {
        (**(code **)(*(wchar_t **)pCVar23 + 8))();
      }
    }
    CoUninitialize();
    goto LAB_141af0778;
  }
  bVar2 = APPCORE::FConverterSupport((APPCORE *)**(undefined8 **)(unaff_GS_OFFSET + 0x58),0x15);
  if (!bVar2) goto LAB_141af0778;
  bStack_eb8 = false;
  pCStack_e90 = (CChart12Converter *)0x0;
  pCStack_e98 = (CExcel12Converter *)0x0;
  uStack_ea8 = 0;
  cStack_eb7 = '\0';
  uStack_e78 = 1;
  uStack_e74 = 1;
  uStack_e70 = 0;
  uStack_e68 = 0x3ff0000000000000;
  uStack_e60 = 0xffffffff;
  uStack_e5c = 0;
  uStack_e58 = 0;
  memset(awStack_248,0,0x202);
  DAT_14299a808 = 0;
  DAT_14299a810 = 0;
  uVar10 = GetCommandLineW();
  pCVar11 = (CChart12Converter *)CommandLineToArgvW(uVar10,&uStack_eb4);
  pCVar20 = pCVar23;
  pCStack_ea0 = pCVar11;
  if (pCVar11 == (CChart12Converter *)0x0) {
LAB_141af0122:
    bVar2 = false;
    VVar26 = 4;
    iVar6 = 10;
    XlsDiag::SendTraceTag
              (0x26c159c,0x354,10,4,
               L"ConvMain: Basic arguments were not valid. format should follow: \'-in <in_path> -ou t <out_path>\' etc."
              );
  }
  else {
    uVar10 = 4;
    uVar24 = 0x32;
    XlsDiag::SendTraceTag
              (0x26c159a,0x354,0x32,4,L"ConvMain: starting command line parse with %d arguments" );
    bVar2 = true;
    iVar4 = 1;
    if ((int)uStack_eb4 < 1) goto LAB_141af0122;
    do {
      iVar6 = FSzEqual(*(wchar_t **)pCVar11,L"-writeSuccessFile");
      if (iVar6 == 0) {
        iVar6 = FSzEqual(*(wchar_t **)pCVar11,L"-quickExitPostConversion");
        if (iVar6 == 0) {
          iVar6 = FSzEqual(*(wchar_t **)pCVar11,L"-oice");
          if ((((iVar6 != 0) || (iVar6 = FSzEqual(*(wchar_t **)pCVar11,L"-oics"), iVar6 != 0)) ||
              (iVar6 = FSzEqual(*(wchar_t **)pCVar11,L"-bcs"), iVar6 != 0)) &&
             (iVar4 + 1 < (int)uStack_eb4)) {
            pCStack_e90 = *(CChart12Converter **)(pCVar11 + 8);
            pCVar23 = *(CChart12Converter **)(pCVar11 + 0x10);
            pAVar21 = (APPCORE *)wcsrchr(pCVar23,0x2e);
            if (pAVar21 != (APPCORE *)0x0) {
              uVar24 = 1;
              SVar7 = SgnSzCompare((wchar_t *)pAVar21,L".xltx",1);
              if (SVar7 == 0) {
                uStack_ea8 = 4;
              }
              else {
                uVar24 = 1;
                SVar7 = SgnSzCompare((wchar_t *)pAVar21,L".xlam",1);
                if (SVar7 == 0) {
                  uStack_ea8 = 3;
                }
                else {
                  uVar24 = 1;
                  pAVar17 = pAVar21;
                  SVar7 = SgnSzCompare((wchar_t *)pAVar21,L".xlsm",1);
                  if ((SVar7 == 0) && (bVar3 = APPCORE::FConverterSupport(pAVar17,2), bVar3)) {
                    uStack_ea8 = 2;
                  }
                  else {
                    uVar24 = 1;
                    pAVar17 = pAVar21;
                    SVar7 = SgnSzCompare((wchar_t *)pAVar21,L".ods",1);
                    if ((SVar7 == 0) && (bVar3 = APPCORE::FConverterSupport(pAVar17,0xf), bVar3))  {
                      uStack_ea8 = 8;
                      ConverterContext::s_fConvertingToODF = 1;
                    }
                    else {
                      uVar24 = 1;
                      pAVar17 = pAVar21;
                      SVar7 = SgnSzCompare((wchar_t *)pAVar21,L".csv",1);
                      if ((SVar7 == 0) && (bVar3 = APPCORE::FConverterSupport(pAVar17,0x14), bVar 3))
                      {
                        uStack_ea8 = 9;
                        ConverterContext::s_fConvertingToCSV = true;
                      }
                      else {
                        uVar24 = 1;
                        pAVar17 = pAVar21;
                        SVar7 = SgnSzCompare((wchar_t *)pAVar21,L".xls*",1);
                        if ((SVar7 == 0) && (bVar3 = APPCORE::FConverterSupport(pAVar17,2), bVar3 ))
                        {
                          ConverterContext::s_fDynamicConversion = 1;
                        }
                        else {
                          pAVar17 = pAVar21;
                          SVar7 = SgnSzCompare((wchar_t *)pAVar21,L".pdf",1);
                          if ((SVar7 == 0) && (bVar3 = APPCORE::FConverterSupport(pAVar17,6), bVa r3)
                             ) {
                            pCVar13 = ConverterContext::PConvPrintSettings();
                            uVar10 = 4;
                            uVar24 = 0x32;
                            XlsDiag::SendTraceTag
                                      (0x650753,0x354,0x32,4,
                                       L"ConverterPrintSettings::SetPrintingToPdf - Converter is pri nting to PDF."
                                      );
                            ConverterPrintSettings::InitDefaultPaperSize(pCVar13);
                            *pCVar13 = (ConverterPrintSettings)0x1;
                            uStack_ea8 = 7;
                          }
                          else {
                            uVar24 = 1;
                            SVar7 = SgnSzCompare((wchar_t *)pAVar21,L".xlsx",1);
                            if (SVar7 == 0) {
                              ConverterContext::s_fStripVBAProject =
                                   FSzEqual(*(wchar_t **)pCVar11,L"-oics");
                            }
                            else {
                              uVar24 = 1;
                              SVar7 = SgnSzCompare((wchar_t *)pAVar21,L".png",1);
                              if (SVar7 == 0) {
                                uStack_e74 = 1;
                                ConverterContext::s_fGeneratingThumbnail = true;
                              }
                              else {
                                uVar24 = 1;
                                SVar7 = SgnSzCompare((wchar_t *)pAVar21,L".jpg",1);
                                if (SVar7 == 0) {
                                  uStack_e74 = 0;
                                  ConverterContext::s_fGeneratingThumbnail = true;
                                }
                                else {
                                  ppuStack_d08 = &Mso::Diagnostics::ClassifiedStructuredObject<>: :
                                                  `vftable';
                                  pcStack_d00 = "Input file extension";
                                  uStack_cf0 = 0x20;
                                  uStack_ce0 = 0;
                                  uStack_cd8 = 0;
                                  uStack_cd0 = 7;
                                  uStack_ce8 = 0;
                                  pcStack_e88 =
                                  "Unknown output extension passed to converter, defaulting to xlsx! "
                                  ;
                                  uVar24 = 10;
                                  pAStack_cf8 = pAVar21;
                                  Mso::Diagnostics::SendDiagnosticTrace<>
                                            (0x64e405,0x354,10,(ValidDataCategories)uVar10,
                                             (StringLiteral<char> *)&pcStack_e88,
                                             (ClassifiedStructuredObject<> *)&ppuStack_d08);
                                  std::basic_string<>::_Tidy_deallocate
                                            ((basic_string<> *)&uStack_ce8);
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
          pCVar13 = ConverterContext::PConvPrintSettings();
          if (*pCVar13 != (ConverterPrintSettings)0x0) {
            pCVar13 = ConverterContext::PConvPrintSettings();
            uVar24 = (ulonglong)uStack_eb4;
            bVar2 = ConverterPrintSettings::FParseFromCmdLineArgs
                              (pCVar13,(wchar_t **)pCStack_ea0,uStack_eb4);
          }
          iVar6 = FSzEqual(*(wchar_t **)pCVar11,L"-repair");
          if (iVar6 != 0) {
            DAT_1429c30f8 = '\x01';
            if ((int)uStack_eb4 <= iVar4) {
              bVar2 = false;
              VVar26 = 4;
              iVar6 = 10;
              XlsDiag::SendTraceTag
                        (0x26c159b,0x354,10,4,
                         L"ConvMain: Repair arguments was not valid. no file path followed the \'-re pair\' flag"
                        );
              break;
            }
            pCStack_e98 = *(CExcel12Converter **)(pCVar11 + 8);
          }
          pAVar21 = *(APPCORE **)pCVar11;
          iVar6 = FSzEqual((wchar_t *)pAVar21,L"-k");
          if ((iVar6 != 0) && (iVar4 < (int)uStack_eb4)) {
            pAVar21 = *(APPCORE **)(pCVar11 + 8);
            iVar8 = OpenAndReadKey((wchar_t *)pAVar21);
            VVar26 = (ValidDataCategories)uVar10;
            iVar6 = (int)uVar24;
            if (iVar8 != 0) goto LAB_141aefd2b;
LAB_141af00fa:
            bVar2 = false;
            break;
          }
LAB_141aefd2b:
          bVar3 = APPCORE::FConverterSupport(pAVar21,0x12);
          if (((bVar3) &&
              (iVar6 = FSzEqual(*(wchar_t **)pCVar11,L"-passwordnamedpipeid"), iVar6 != 0)) &&
             (iVar4 < (int)uStack_eb4)) {
            iVar8 = OpenPipeAndReadPassword(*(wchar_t **)(pCVar11 + 8),awStack_248);
            VVar26 = (ValidDataCategories)uVar10;
            iVar6 = (int)uVar24;
            if (iVar8 == 0) goto LAB_141af00fa;
          }
          iVar6 = FSzEqual(*(wchar_t **)pCVar11,L"-flightodfrepairenabled");
          if (iVar6 != 0) {
            ConverterContext::s_fConverterOdfFileRepairEnabled = true;
          }
          iVar6 = FSzEqual(*(wchar_t **)pCVar11,L"-mdp");
          if ((iVar6 != 0) && (iVar4 < (int)uStack_eb4)) {
            ConverterContext::s_wzPathToWriteMetadataFile = *(wchar_t **)(pCVar11 + 8);
            ConverterContext::s_fWriteMetadataFile = true;
          }
          iVar6 = FSzEqual(*(wchar_t **)pCVar11,L"-keepPDFProtection");
          if (iVar6 != 0) {
            ConverterContext::s_fKeepPDFProtection = true;
          }
          iVar6 = FSzEqual(*(wchar_t **)pCVar11,L"-clpTenantId");
          if ((iVar6 != 0) && (iVar4 < (int)uStack_eb4)) {
            ConverterContext::s_wzTenantId = *(wchar_t **)(pCVar11 + 8);
          }
          iVar6 = FSzEqual(*(wchar_t **)pCVar11,L"-clpSupportsOfficeClientCoauthoring");
          if (iVar6 != 0) {
            ConverterContext::s_fSupportsOfficeClientCoauthoring = true;
          }
          iVar6 = FSzEqual(*(wchar_t **)pCVar11,L"-allowMismatchedFileFormatConversionForBCS");
          if (iVar6 != 0) {
            ConverterContext::s_fAllowMismatchedFileFormatConversionForBCS = true;
          }
        }
        else {
          uVar10 = 4;
          uVar24 = 0x32;
          XlsDiag::SendTraceTag
                    (0x1e623149,0x354,0x32,4,L"ConvMain: Exit post conversion switch engaged.");
          bStack_eb8 = true;
        }
      }
      else {
        uVar10 = 4;
        uVar24 = 0x32;
        XlsDiag::SendTraceTag
                  (0x1e61735e,0x354,0x32,4,L"ConvMain: write temp file on successful conversion." );
        cStack_eb0 = '\x01';
      }
      VVar26 = (ValidDataCategories)uVar10;
      iVar6 = (int)uVar24;
      pCVar11 = pCVar11 + 8;
      bVar3 = iVar4 < (int)uStack_eb4;
      iVar4 = iVar4 + 1;
    } while (bVar3);
    pCVar20 = pCStack_e90;
    if (((pCStack_e90 == (CChart12Converter *)0x0) || (pCVar23 == (CChart12Converter *)0x0)) ||
       ((DAT_1429c30f8 != '\0' && (pCStack_e98 == (CExcel12Converter *)0x0)))) goto LAB_141af0122 ;
  }
  pCVar11 = pCStack_ea0;
  if (ConverterContext::s_fGeneratingThumbnail != false) {
    pTVar25 = (ThumbnailParams *)&uStack_e78;
    bVar2 = FParseCmdLineArgsThumbnail((wchar_t **)pCStack_ea0,uStack_eb4,pTVar25);
    iVar6 = (int)pTVar25;
  }
  cVar22 = cStack_eb7;
  if ((pCVar20 != (CChart12Converter *)0x0) &&
     (lVar12 = wcsrchr(pCVar20), cVar22 = cStack_eb7, lVar12 != 0)) {
    iVar6 = 1;
    iVar4 = Ordinal_55665(lVar12);
    if (iVar4 == 0) {
      iVar6 = 1;
      iVar4 = Ordinal_55665(lVar12);
      cVar22 = cStack_eb7;
      if (iVar4 == 0) goto LAB_141af01c3;
    }
    cVar22 = '\x01';
  }
LAB_141af01c3:
  lVar12 = **(longlong **)(unaff_GS_OFFSET + 0x58);
  if ((((*(int *)(*(longlong *)(lVar12 + 0x10) + 0xb9c) != 0) &&
       (pCVar13 = ConverterContext::PConvPrintSettings(), *pCVar13 == (ConverterPrintSettings)0x 0))
      && (cVar22 == '\0')) &&
     ((DAT_1429c30f8 == '\0' && (ConverterContext::s_fConvertingToCSV == false)))) {
    VVar26 = 4;
    iVar6 = 10;
    XlsDiag::SendTraceTag
              (0x64e406,0x354,10,4,
               L"ConvMain: Using fake LCIDs is only supported for printing to PDF or converting CSV/ SKV files."
              );
    bVar2 = false;
  }
  if ((*(int *)(*(longlong *)(lVar12 + 0x10) + 0xba8) != 0) &&
     (pCVar13 = ConverterContext::PConvPrintSettings(), *pCVar13 == (ConverterPrintSettings)0x0) ) {
    VVar26 = 4;
    iVar6 = 10;
    XlsDiag::SendTraceTag
              (0x2169b596,0x354,10,4,
               L"ConvMain: Using fake Hculture is only supported for printing to PDF.");
    bVar2 = false;
  }
  if (bVar2 == false) {
    pAStack_cf8 = (APPCORE *)GetCommandLineW();
    ppuStack_d08 = &Mso::Diagnostics::ClassifiedStructuredObject<>::`vftable';
    pcStack_d00 = "Command line arguments";
    uStack_cf0 = 0x20;
    uStack_ce0 = 0;
    uStack_cd8 = 0;
    uStack_cd0 = 7;
    uStack_ce8 = 0;
    pcStack_e88 = "Invalid command line arguments passed to converter";
    Mso::Diagnostics::SendDiagnosticTrace<>
              (0x64e409,0x354,10,VVar26,(StringLiteral<char> *)&pcStack_e88,
               (ClassifiedStructuredObject<> *)&ppuStack_d08);
    std::basic_string<>::_Tidy_deallocate((basic_string<> *)&uStack_ce8);
    ConverterContext::s_scfcConversionError = 0x100000;
  }
  else {
    pCVar13 = ConverterContext::PConvPrintSettings();
    pAVar21 = (APPCORE *)0x0;
    if (*pCVar13 != (ConverterPrintSettings)0x0) {
      iVar6 = 4;
      EnumFaceNames((wchar_t *)0x0,(FLST *)0x0,4,VVar26);
    }
    awStack_458[0] = L'\0';
    if (0 < (int)uStack_eb4) {
      AddOfficeSymbolFont(*(wchar_t **)pCVar11,awStack_458,iVar6);
    }
    uStack_a78 = 0;
    if (awStack_248[0] == L'\0') {
      awStack_868[0] = L'\0';
    }
    else {
      CchSzToSt(awStack_248,awStack_868,0x101);
    }
    uStack_666 = 0;
    uStack_86c = uStack_ea8;
    auStack_c88[0] = 0;
    pnVar18 = anStack_a74;
    MsoWzCopy((wchar_t *)pCStack_e90,(wchar_t *)pnVar18,0x104);
    pAVar14 = (APPCORE *)operator_new(0x38,pnVar18);
    pAVar17 = pAVar21;
    if (pAVar14 != (APPCORE *)0x0) {
      *(undefined ***)pAVar14 = &CExcel12Converter::`vftable'{for_`IExcel12Converter'};
      *(undefined ***)(pAVar14 + 8) = &CExcel12Converter::`vftable'{for_`IClassFactory'};
      *(longlong *)(pAVar14 + 0x28) = 0;
      *(longlong *)(pAVar14 + 0x30) = 0;
      *(longlong *)(pAVar14 + 0x10) = 0;
      *(longlong *)(pAVar14 + 0x20) = 0;
      pAVar17 = pAVar14;
    }
    if (pAVar17 != (APPCORE *)0x0) {
      iVar4 = (**(code **)(*(longlong *)pAVar17 + 0x18))(pAVar17);
      if (-1 < iVar4) {
        XlsDiag::SendTraceTag
                  (0x64e407,0x354,0x32,4,L"ConvMain: Calling converter to begin conversion.");
        if (ConverterContext::s_fGeneratingThumbnail != false) {
          *(undefined4 **)(pAVar17 + 0x28) = &uStack_e78;
        }
        bVar2 = InCellControlsFlighting::FForceInCellControlsPrintingInConverter();
        if (bVar2) {
          *(wchar_t **)(pAVar17 + 0x30) = awStack_458;
        }
        iVar4 = (**(code **)(*(longlong *)pAVar17 + 0x28))(pAVar17);
        pAVar14 = pAVar17;
        (**(code **)(*(longlong *)pAVar17 + 0x30))();
        if (-1 < iVar4) {
          bVar2 = APPCORE::FConverterSupport(pAVar14,3);
          if (bVar2) {
            if (ConverterContext::s_fDynamicallyConvertedToXlsm == 0) {
              pAVar14 = (APPCORE *)0xffffffffffffffff;
              if (pCVar23 != (CChart12Converter *)0x0) {
                do {
                  pAVar21 = pAVar14 + 1;
                  pAVar14 = pAVar21;
                } while (*(short *)(pCVar23 + (longlong)pAVar21 * 2) != 0);
              }
              *(undefined2 *)(pCVar23 + (longlong)(int)pAVar21 * 2 + -2) = 0x78;
            }
            else {
              pAVar14 = (APPCORE *)0xffffffffffffffff;
              if (pCVar23 != (CChart12Converter *)0x0) {
                do {
                  pAVar21 = pAVar14 + 1;
                  pAVar14 = pAVar21;
                } while (*(short *)(pCVar23 + (longlong)pAVar21 * 2) != 0);
              }
              *(undefined2 *)(pCVar23 + (longlong)(int)pAVar21 * 2 + -2) = 0x6d;
              XlsDiag::SendTraceTag
                        (0x65d321,0x354,0x32,4,
                         L"ConvMain: Setting \'error\' code to scfcDynamicXlsmConversion to signal t hat we dynamically converted to xlsm."
                        );
              ConverterContext::s_scfcConversionError = 0xc0000;
            }
          }
          XlsDiag::SendTraceTag(0x1e3d60db,0x354,0x32,4,L"ConvMain: Copying file.");
          this = auStack_c88;
          CopyFileW(this,pCVar23,0);
          if (DAT_1429c30fa != 0) {
            this = &DAT_1429c30fa;
            CopyFileW(&DAT_1429c30fa,pCStack_e98,0);
          }
          bVar2 = APPCORE::FConverterSupport((APPCORE *)this,0x1a);
          if ((bVar2) && (ConverterContext::s_fWriteMetadataFile != false)) {
            ConverterContext::WriteMetadataFile();
          }
          iVar4 = 4;
          XlsDiag::SendTraceTag
                    (0x64e408,0x354,0x32,4,L"ConvMain: Conversion completed successfully.");
          if (cStack_eb0 != '\0') {
            uStack_cc0 = 0;
            uStack_cb8 = 0;
            uStack_cb0 = 7;
            uStack_cc8 = 0;
            iVar6 = std::basic_string<>::basic_string<>((basic_string<> *)&ppuStack_d08,L".tmp") ;
            pbVar15 = (basic_string<> *)std::operator+<>(abStack_ca8,pCVar23);
            std::basic_string<>::operator=((basic_string<> *)&uStack_cc8,pbVar15);
            std::basic_string<>::_Tidy_deallocate(abStack_ca8);
            std::basic_string<>::_Tidy_deallocate((basic_string<> *)&ppuStack_d08);
            std::basic_ofstream<>::basic_ofstream<>
                      ((basic_ofstream<> *)&lStack_e18,(basic_string<> *)&uStack_cc8,iVar6,iVar4) ;
            std::operator<<<>((basic_ostream<> *)&lStack_e18,
                              "Temp file created for successful conversions.");
            pbVar16 = std::basic_filebuf<>::close(abStack_e10);
            if (pbVar16 == (basic_filebuf<> *)0x0) {
              ?setstate@?$basic_ios@DU?$char_traits@D@std@@@std@@QEAAXH_N@Z
                        (abStack_e10 + (longlong)*(int *)(lStack_e18 + 4) + -8);
            }
            std::basic_ofstream<>::`vbase_destructor'((basic_ofstream<> *)&lStack_e18);
            std::basic_string<>::_Tidy_deallocate((basic_string<> *)&uStack_cc8);
          }
        }
      }
      if (bStack_eb8 != false) {
        XlsDiag::SendTraceTag
                  (0x1e623148,0x354,0x32,4,L"ConvMain: Exiting via post conversion switch.");
        uVar10 = GetCurrentProcess();
        TerminateProcess(uVar10);
      }
      Ordinal_53248(pAVar17);
    }
    if ((awStack_458[0] != L'\0') && (iVar4 = RemoveFontResourceExW(awStack_458), iVar4 == 0)) {
      XlsDiag::SendTraceTag
                (0x258e8e0,0x354,10,4,L"ConvMain: Unable to uninstall Office Symbol font.");
    }
  }
  if (pCVar11 != (CChart12Converter *)0x0) {
    LocalFree(pCVar11);
  }
  if (DAT_14299a808 != 0) {
    Ordinal_53248();
  }
LAB_141af0778:
  if (pCStack_e80 != (CChart12Converter *)0x0) {
    Mso::ActivityScope::ScopeHolder::`scalar_deleting_destructor'((ScopeHolder *)pCStack_e80,1) ;
  }
  uStack_ea8 = 0;
  lVar5 = HrDoQuit((OPER **)0x0,0,0,(int *)&uStack_ea8);
  if (-1 < lVar5) {
    iVar4 = __security_check_cookie(uStack_38 ^ (ulonglong)auStackY_ee8);
    return iVar4;
  }
  CrashOrDoJmpHr(1,*(ENV **)(*(longlong *)(**(longlong **)(unaff_GS_OFFSET + 0x58) + 0x10) + 0x15 0),
                 lVar5,0x1f107701);
  pcVar1 = (code *)swi(3);
  iVar4 = (*pcVar1)();
  return iVar4;
}
```


For starters, we probably want to display the debug messages, so let's take a look at the trace stuff..



```
/* public: static void __cdecl XlsDiag::SendTraceTag(unsigned long,enum Mso::Logging::Category,enum
   Mso::Logging::Severity,enum Mso::Logging::DataClassifications,wchar_t const * __ptr64,...) */

void __cdecl
XlsDiag::SendTraceTag
          (ulong param_1,Category param_2,Severity param_3,DataClassifications param_4,
          wchar_t *param_5,...)

{
  SendTraceVTag(param_1,param_2,param_3,param_4,param_5,&stack0x00000030);
  return;
}
```

Ok, so I think this is actually quite easy to fuzz, because we can just loop in this function here maybe?????????????

Before jumping in as usual, let's try to reverse this function a bit more... (maybe this can help us speed up the fuzzing process a bit? Maybe we can patch some unimportant stuff out???)

Actually we need to do some patching, because there exists an exit condition here:
```
  lVar5 = HrDoQuit((OPER **)0x0,0,0,(int *)&local_ea8);
  if (-1 < lVar5) {
    iVar4 = __security_check_cookie(local_38 ^ (ulonglong)auStackY_ee8);
    return iVar4; // <-- THIS IS BAD FOR FUZZING
  }
  CrashOrDoJmpHr(...); // <-- Also BAD
```
and we need to patch out the call to HrDoQuit and also make the next if case to always jump. This way the function returns always...

Here is the disassembly:

```
       141af079c 33  c9           XOR        ECX ,ECX
       141af079e e8  dd  c9       CALL       HrDoQuit                                         long HrDoQuit(OPER * * param_1,
                 c2  fe
       141af07a3 85  c0           TEST       EAX ,EAX
       141af07a5 78  3a           JS         LAB_141af07e1
       141af07a7 41  f7  d6       NOT        R14D
       141af07aa 41  c1  ee       SHR        R14D ,0x1f
                 1f
```


So now we just patch the stuff out and we should be good correct?

Let's try it out!!!

Here is my patch script:

```

#!/bin/sh

'''
       141af0797 45  33  c0       XOR        R8D ,R8D
       141af079a 33  d2           XOR        EDX ,EDX
       141af079c 33  c9           XOR        ECX ,ECX
       141af079e e8  dd  c9       CALL       HrDoQuit                                         long HrDoQuit(OPER * * param_1,
                 c2  fe
       141af07a3 85  c0           TEST       EAX ,EAX
       141af07a5 78  3a           JS         LAB_141af07e1
       141af07a7 41  f7  d6       NOT        R14D
       141af07aa 41  c1  ee       SHR        R14D ,0x1f
                 1f
       141af07ae 41  8b  c6       MOV        EAX ,R14D

'''

ORIG_BYTES = "45  33  c0  33  d2  33  c9  e8  dd  c9 c2  fe  85  c0  78  3a  41  f7  d6"
ORIG_BYTES = ORIG_BYTES.replace(" ", "") # Remove spaces.
# Now convert to actual bytes
ORIG_BYTES = bytes.fromhex(ORIG_BYTES)

NEW_BYTES = "45  33  c0  33  d2  33  c9  90 90 90 90 90  85  c0  90  90  41  f7  d6"
NEW_BYTES = NEW_BYTES.replace(" ", "") # Remove spaces.
# Now convert to actual bytes
NEW_BYTES = bytes.fromhex(NEW_BYTES)

INPUT_FILENAME = "input_binary.exe"
OUTPUT_FILENAME = "excelcnv_output.exe"

def xxd(data: bytes, width: int = 16):
	for i in range(0, len(data), width):
		chunk = data[i:i+width]
		hex_bytes = ' '.join(f"{b:02x}" for b in chunk)
		ascii_bytes = ''.join((chr(b) if 32 <= b < 127 else '.') for b in chunk)
		print(f"{i:08x}  {hex_bytes:<{width*3}}  {ascii_bytes}")

def patch():
	fh = open(INPUT_FILENAME, "rb")
	orig_data = fh.read()
	fh.close()
	offset_stuff = 0x1af0797 # Offset into the thing...
	how_many = 0x30
	the_buffer = orig_data[offset_stuff:offset_stuff+how_many]
	xxd(the_buffer)
	assert ORIG_BYTES in orig_data
	count = orig_data.count(ORIG_BYTES)
	print("Here is the count: "+str(count))
	assert count == 1 # Should only be one instance of such bytestring
	new_data = orig_data.replace(ORIG_BYTES, NEW_BYTES)
	fh = open(OUTPUT_FILENAME, "wb")
	fh.write(new_data)
	fh.close()
	return


if __name__=="__main__":
	patch()
	exit(0)

```

Now, this is not enough, because we need to add a call to the HrDoQuit function, because during the initial run of the program during fuzzing, this fails. It fails because before entering the persistent loop, winafl runs the program initially from start to end and therefore it crashes.

Let's try to add a call to the HrDoQuit function...

The decomp of this stuff here:

```
      ConvMainLoop();
      Ordinal_13352(local_6d0);
      goto LAB_14000e9cb;

```

is this here:


```

       14000e9b7 e8  e4  0e       CALL       ConvMainLoop                                     int ConvMainLoop(void)
                 ae  01
       14000e9bc 48  8d  4c       LEA        RCX => local_6d0 ,[RSP  + 0x78 ]
                 24  78
       14000e9c1 8b  d8           MOV        EBX ,EAX
       14000e9c3 ff  15  97       CALL       qword ptr [-> MSO20WIN32CLIENT.DLL::Ordinal_133  = 1408c7056
                 0a  b5  02
       14000e9c9 8b  c3           MOV        EAX ,EBX
                             LAB_14000e9cb                                   XREF[1]:     14000ea1d (j)
       14000e9cb 48  8b  8d       MOV        RCX ,qword ptr [RBP  + local_58 ]
                 f0  05  00
                 00


```

Therefore starting with address `0x14000e9c9` I think we should just put the stuff there..



## Changing strategies

Ok, so I now have a working fuzzer. Now I can fuzz excel files all good. There is a problem however, because the input files are zip files and that zip file essentially contains a lot of xml files, mutating this file in smart ways is quite hard, and as such I have decided to fuzz the older file formats itself. We can simply use the excelcnv utility to convert modern style files to the older file format. Now I am going to write a custom mutator for this file format, because reasons. It is a block style format and because of this traditional fuzzers corrupt the blocks in such ways such that the entire rest of the file becomes invalid.
































