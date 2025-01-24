# Fuzzing ORGCHART.EXE

ORGCHART.EXE is a binary bundled with Microsoft Office which you can use to manipulate OPX files which are files which describe organizational structures.

## Reversing the binary.

Just looking at the binary, there doesn't seem to be a lot going on. It seems that ORGCHART.EXE just calls some external functions in some DLL which actually do the heavy lifting. Therefore I think that should start with running it in x64dbg first and see what kinds of function calls we get.

## Initial observations

First of all, the binary calls `kernel32.ReadFile` to read the file initially into a buffer.


Here is basically the call stack of the program:

```
,000000E7356FE0B8,00007FF69A6878EB,00007FF960B409A0,60,KÃ¤yttÃ¤jÃ¤alue,kernel32.ReadFile
,000000E7356FE118,00007FF69A687AA5,00007FF69A6878EB,40,KÃ¤yttÃ¤jÃ¤alue,orgchart.00007FF69A6878EB
,000000E7356FE158,00007FF69A6A4AF6,00007FF69A687AA5,6E0,KÃ¤yttÃ¤jÃ¤alue,orgchart.00007FF69A687AA5
,000000E7356FE838,00007FF69A6A519F,00007FF69A6A4AF6,6C0,KÃ¤yttÃ¤jÃ¤alue,orgchart.00007FF69A6A4AF6
,000000E7356FEEF8,00007FF69A6A5B4E,00007FF69A6A519F,40,KÃ¤yttÃ¤jÃ¤alue,orgchart.00007FF69A6A519F
,000000E7356FEF38,00007FF69A6A5C9F,00007FF69A6A5B4E,150,KÃ¤yttÃ¤jÃ¤alue,orgchart.00007FF69A6A5B4E
,000000E7356FF088,00007FF69A6976DF,00007FF69A6A5C9F,50,KÃ¤yttÃ¤jÃ¤alue,orgchart.00007FF69A6A5C9F
,000000E7356FF0D8,00007FF69A697F98,00007FF69A6976DF,9E0,KÃ¤yttÃ¤jÃ¤alue,orgchart.00007FF69A6976DF
,000000E7356FFAB8,00007FF960C183F1,00007FF69A697F98,160,JÃ¤rjestelmÃ¤,orgchart.00007FF69A697F98
,000000E7356FFC18,00007FF960C17EB1,00007FF960C183F1,80,JÃ¤rjestelmÃ¤,user32.DispatchMessageW+741
,000000E7356FFC98,00007FF69A698D81,00007FF960C17EB1,1D0,KÃ¤yttÃ¤jÃ¤alue,user32.DispatchMessageW+201
,000000E7356FFE68,00007FF69A6CD472,00007FF69A698D81,40,KÃ¤yttÃ¤jÃ¤alue,orgchart.00007FF69A698D81
,000000E7356FFEA8,00007FF960B3259D,00007FF69A6CD472,30,JÃ¤rjestelmÃ¤,orgchart.00007FF69A6CD472
,000000E7356FFED8,00007FF96200AF38,00007FF960B3259D,80,JÃ¤rjestelmÃ¤,kernel32.BaseThreadInitThunk+1D
,000000E7356FFF58,0000000000000000,00007FF96200AF38,,KÃ¤yttÃ¤jÃ¤alue,ntdll.RtlUserThreadStart+28
```

here is the decompilation of where the ReadFile function gets called:

```
ulonglong FUN_1400477fc(LPCSTR param_1,HANDLE param_2,uint *param_3,DWORD param_4,int *param_5)

{
  short *psVar1;
  DWORD DVar2;
  BOOL BVar3;
  uint uVar4;
  short *psVar5;
  longlong lVar6;
  undefined *puVar7;
  short sVar8;
  ulonglong uVar9;
  uint uVar10;
  ulonglong uVar11;
  uint uVar12;
  DWORD local_res20 [2];

  uVar9 = 0;
  uVar12 = 0;
  uVar10 = 0xffffffff;
  if (0 < (longlong)*DAT_1400bb4f0) {
    psVar5 = DAT_1400bb4f0 + 5;
    uVar11 = uVar9;
    do {
      uVar10 = (uint)uVar11;
      if (*psVar5 == 0) break;
      uVar11 = (ulonglong)((uint)uVar11 + 1);
      uVar9 = uVar9 + 1;
      psVar5 = psVar5 + 0x6d;
      uVar10 = 0xffffffff;
    } while ((longlong)uVar9 < (longlong)*DAT_1400bb4f0);
  }
  if ((int)uVar10 < 0) {
    uVar9 = 2;
  }
  else {
    *param_3 = uVar10;
    local_res20[0] = param_4;
    if ((param_1 == (LPCSTR)0x0) ||
       (param_2 = (HANDLE)FUN_14007ef7c(param_1,2), param_2 != (HANDLE)0xffffffffffffffff)) {
      lVar6 = (longlong)(int)uVar10;
      DVar2 = SetFilePointer(param_2,0,(PLONG)0x0,0);
      if ((DVar2 == 0xffffffff) ||
         (BVar3 = ReadFile(param_2,DAT_1400bb4f0 + lVar6 * 0x6d + 1,0xda,local_res20,
                           (LPOVERLAPPED)0x0), psVar5 = DAT_1400bb4f0, BVar3 == 0)) {
        uVar9 = 0x2713;
      }
      else {
        if (DAT_1400bb4f0[lVar6 * 0x6d + 1] == 2) {
          if (*(int *)(DAT_1400bb4f0 + lVar6 * 0x6d + 3) == 0) {
            uVar4 = uVar12;
            if (DAT_1400bb4f0[lVar6 * 0x6d + 2] != -1) {
              uVar4 = 7;
            }
            uVar9 = (ulonglong)uVar4;
          }
          else {
            uVar9 = 6;
          }
        }
        else {
          uVar9 = 7;
        }
        if ((int)uVar9 == 0) {
          *param_5 = (int)DAT_1400bb4f0[lVar6 * 0x6d + 2];
          sVar8 = (short)uVar9 + 0xc;
          if ((*(byte *)(psVar5 + lVar6 * 0x6d + 5) & 4) == 0) {
            sVar8 = (short)uVar9 + 8;
          }
          psVar5[lVar6 * 0x6d + 5] = sVar8;
          uVar12 = 1;
          *(HANDLE *)(psVar5 + lVar6 * 0x6d + 6) = param_2;
          psVar1 = psVar5 + lVar6 * 0x6d + 0x26;
          psVar1[0] = 0;
          psVar1[1] = 0;
          psVar1[2] = 0;
          psVar1[3] = 0;
          psVar1 = psVar5 + lVar6 * 0x6d + 0x14;
          psVar1[0] = 0;
          psVar1[1] = 0;
          psVar1[2] = 0;
          psVar1[3] = 0;
          psVar1 = psVar5 + lVar6 * 0x6d + 0x1d;
          psVar1[0] = 0;
          psVar1[1] = 0;
          psVar1[2] = 0;
          psVar1[3] = 0;
          puVar7 = FUN_140046c20(psVar5 + lVar6 * 0x6d + 0x21,uVar10,-4);
          if ((int)puVar7 == 0) {
            puVar7 = FUN_140046c20(DAT_1400bb4f0 + lVar6 * 0x6d + 0xf,uVar10,-4);
          }
          uVar9 = (ulonglong)puVar7 & 0xffffffff;
          if ((int)puVar7 == 0) {
            return uVar9;
          }
        }
        if (uVar12 != 0) {
          if (*(HGLOBAL *)(DAT_1400bb4f0 + lVar6 * 0x6d + 0x26) != (HGLOBAL)0x0) {
            GlobalFree(*(HGLOBAL *)(DAT_1400bb4f0 + lVar6 * 0x6d + 0x26));
          }
          if (*(HGLOBAL *)(DAT_1400bb4f0 + lVar6 * 0x6d + 0x14) != (HGLOBAL)0x0) {
            GlobalFree(*(HGLOBAL *)(DAT_1400bb4f0 + lVar6 * 0x6d + 0x14));
          }
        }
      }
      if (param_1 != (LPCSTR)0x0) {
        CloseHandle(param_2);
      }
      DAT_1400bb4f0[lVar6 * 0x6d + 5] = 0;
    }
    else {
      uVar9 = 0x2713;
    }
  }
  return uVar9;
}
```

I tried to change one byte in text in the original input file and then the program claimed that the file was invalid, therefore we can assume that there is probably some checksum checking going on or something like that, since this happens...

## Reversing the checksum check

Usually the checksum appears in the very header of the file, and then that checksum is checked against the actual body of the file.

So if we advance through the call stack, the aforementioned function was actually called from this function here:

```


void FUN_140047a70(HANDLE param_1,uint *param_2,undefined8 param_3,DWORD param_4)

{
  int iVar1;
  DWORD local_res20 [2];

  local_res20[0] = param_4;
  iVar1 = FUN_14004751c(param_1);
  if (iVar1 == 0) {
    FUN_1400477fc((LPCSTR)0x0,param_1,param_2,param_4,(int *)local_res20);
  }
  return;
}


```

my guess is that FUN_14004751c is a function which checks if the file actually exists and then FUN_1400477fc tries to process said file...

Here is a reversed function:

```

void FUN_140047a70(HANDLE filename,uint *param_2,undefined8 param_3,DWORD param_4)

{
  int iVar1;
  DWORD local_res20 [2];

  local_res20[0] = param_4;
  iVar1 = check_file_exists(filename);
  if (iVar1 == 0) {
    maybe_process_file((LPCSTR)0x0,filename,param_2,param_4,(int *)local_res20);
  }
  return;
}



```

Let's go up the call stack again a bit...

Here is the calling function again:

```

void FUN_1400648c8(HWND param_1,uint param_2,int param_3,int param_4,LPCSTR param_5,uint *param_ 6)

{
  char cVar1;
  bool bVar2;
  bool bVar3;
  bool bVar4;
  bool bVar5;
  int iVar6;
  DWORD DVar7;
  int extraout_EAX;
  HGLOBAL hMem;
  uint *puVar8;
  char *pcVar9;
  HANDLE pvVar10;
  uint *puVar11;
  ulonglong uVar12;
  char *pcVar13;
  uint *puVar14;
  LPCSTR pCVar15;
  undefined8 uVar16;
  uint *puVar17;
  longlong lVar18;
  longlong lVar19;
  longlong lVar20;
  LPSTR lpTempFileName;
  HANDLE pvVar21;
  undefined auStackY_6d8 [32];
  int local_690 [2];
  HWND local_688;
  CHAR local_678 [272];
  CHAR local_568 [272];
  WCHAR local_458 [264];
  wchar_t local_248 [264];
  ulonglong local_38;

  local_38 = DAT_140098000 ^ (ulonglong)auStackY_6d8;
  bVar4 = false;
  bVar5 = false;
  bVar2 = false;
  local_688 = param_1;
  hMem = GlobalAlloc(2,0x230);
  if (hMem == (HGLOBAL)0x0) goto LAB_140064a77;
  puVar8 = (uint *)GlobalLock(hMem);
  GetTempPathA(0x104,local_568);
  lpTempFileName = local_678;
  GetTempFileNameA(local_568,"OPWTMP",0,lpTempFileName);
  DVar7 = (DWORD)lpTempFileName;
  pcVar13 = (char *)((longlong)puVar8 + 0x10a);
  lVar19 = 0x106;
  lVar18 = 0x106;
  lVar20 = -(longlong)pcVar13;
  do {
    if ((lVar18 == -0x7ffffef8) || (pcVar13[(longlong)(local_678 + lVar20)] == '\0')) break;
    *pcVar13 = pcVar13[(longlong)(local_678 + lVar20)];
    pcVar13 = pcVar13 + 1;
    lVar18 = lVar18 + -1;
  } while (lVar18 != 0);
  pcVar9 = pcVar13 + -1;
  if (lVar18 != 0) {
    pcVar9 = pcVar13;
  }
  *pcVar9 = '\0';
  pvVar10 = (HANDLE)FUN_14007ef7c(local_678,2);
  *(HANDLE *)(puVar8 + 0x86) = pvVar10;
  if (pvVar10 == (HANDLE)0xffffffffffffffff) {
LAB_1400649f1:
    iVar6 = 0x2717;
    bVar3 = bVar4;
  }
  else {
    bVar2 = true;
    puVar8[0x89] = 3 - (param_4 != 0);
    puVar8[0x8b] = 0;
    puVar8[0x8a] = 1;
    if (((param_2 == 0) || (param_3 != 0)) && (param_4 == 0)) {
      puVar14 = puVar8 + 1;
      *puVar8 = -(uint)(param_3 != 0) & param_2;
      puVar17 = puVar14;
      do {
        if ((lVar19 == -0x7ffffef8) ||
           (cVar1 = *(char *)(((longlong)param_5 - (longlong)puVar14) + (longlong)puVar17),
           cVar1 == '\0')) break;
        *(char *)puVar17 = cVar1;
        puVar17 = (uint *)((longlong)puVar17 + 1);
        lVar19 = lVar19 + -1;
      } while (lVar19 != 0);
      puVar11 = (uint *)((longlong)puVar17 + -1);
      if (lVar19 != 0) {
        puVar11 = puVar17;
      }
      *(char *)puVar11 = '\0';
      pvVar10 = (HANDLE)FUN_14007ef7c(param_5,2);
      *(HANDLE *)(puVar8 + 0x84) = pvVar10;
      bVar3 = true;
      if (pvVar10 == (HANDLE)0xffffffffffffffff) {
        pvVar10 = (HANDLE)FUN_14007ef7c(param_5,0);
        *(HANDLE *)(puVar8 + 0x84) = pvVar10;
        if (pvVar10 == (HANDLE)0xffffffffffffffff) goto LAB_1400649f1;
        puVar8[0x8b] = 1;
      }
      pvVar21 = *(HANDLE *)(puVar8 + 0x86);
      FUN_140062f6c(param_5,pvVar10,1,pvVar21,0);
      iVar6 = extraout_EAX;
      if (extraout_EAX == 0) {
        uVar12 = maybe_process_file((LPCSTR)0x0,*(HANDLE *)(puVar8 + 0x86),puVar8 + 0x88,
                                    (DWORD)pvVar21,local_690);
        iVar6 = (int)uVar12;
        if (iVar6 == 0) {
          *param_6 = puVar8[0x88];
          if (param_3 == 0) {
            FUN_14006296c((char *)puVar14);
          }
          CloseHandle(*(HANDLE *)(puVar8 + 0x84));
          puVar8[0x84] = 0xffffffff;
          puVar8[0x85] = 0xffffffff;
          bVar3 = false;
        }
      }
    }
    else {
      puVar14 = puVar8 + 0x88;
      *puVar8 = param_2;
      iVar6 = check_and_process_maybe(pvVar10,puVar14,pvVar10,DVar7);
      bVar3 = bVar5;
      if (iVar6 == 0) {
        *param_6 = *puVar14;
        iVar6 = FUN_14006480c(*puVar14);
        if ((iVar6 == 0) && (param_2 == 0)) {
          puVar14 = puVar8 + 1;
          lVar20 = 0x105;
          lVar18 = (longlong)param_5 - (longlong)puVar14;
          do {
            if ((lVar20 == -0x7ffffef9) ||
               (cVar1 = *(char *)(lVar18 + (longlong)puVar14), cVar1 == '\0')) break;
            *(char *)puVar14 = cVar1;
            puVar14 = (uint *)((longlong)puVar14 + 1);
            lVar20 = lVar20 + -1;
          } while (lVar20 != 0);
          puVar17 = (uint *)((longlong)puVar14 + -1);
          if (lVar20 != 0) {
            puVar17 = puVar14;
          }
          *(char *)puVar17 = '\0';
          pCVar15 = param_5;
          lVar20 = FUN_14007ef7c(param_5,2);
          *(longlong *)(puVar8 + 0x84) = lVar20;
          bVar3 = true;
          if (lVar20 == -1) {
            DVar7 = GetLastError();
            if ((DVar7 < 0x21) && ((0x100080020U >> ((ulonglong)DVar7 & 0x3f) & 1) != 0)) {
              MultiByteToWideChar(0,1,param_5,-1,local_458,0x105);
              uVar16 = 0x84;
              if (DVar7 != 0x20) {
                uVar16 = 0x86;
              }
              FUN_14007ead4((UINT)uVar16,(va_list)local_458,local_248);
              iVar6 = FUN_140057350(uVar16,local_248,4);
              if (iVar6 == 7) {
                iVar6 = 0x2717;
                bVar3 = bVar4;
              }
              else {
                lVar20 = FUN_14007ef7c(param_5,0);
                *(longlong *)(puVar8 + 0x84) = lVar20;
                if (lVar20 == -1) {
                  iVar6 = 0x2717;
                  bVar3 = bVar4;
                }
                else {
                  puVar8[0x8b] = 1;
                  iVar6 = 0;
                }
              }
            }
            else {
              FUN_140068a6c(pCVar15,DVar7);
              iVar6 = -1;
              bVar3 = bVar5;
            }
          }
        }
      }
    }
  }
  if (iVar6 == 0) {
    SetWindowLongPtrA(local_688,0,(LONG_PTR)hMem);
  }
  else {
    if (bVar2) {
      CloseHandle(*(HANDLE *)(puVar8 + 0x86));
    }
    if (bVar3) {
      CloseHandle(*(HANDLE *)(puVar8 + 0x84));
    }
    DeleteFileA(local_678);
    if ((puVar8[0x8b] != 0) && (bVar3)) {
      CloseHandle(*(HANDLE *)(puVar8 + 0x84));
      puVar8[0x84] = 0xffffffff;
      puVar8[0x85] = 0xffffffff;
    }
  }
  GlobalUnlock(hMem);
LAB_140064a77:
  FUN_14008d510(local_38 ^ (ulonglong)auStackY_6d8);
  return;
}

```


Here is the thing:

```

void FUN_1400648c8(HWND param_1,uint param_2,int param_3,int param_4,LPCSTR maybefilenamestring,
                  uint *param_6)

{
  char cVar1;
  bool bVar2;
  bool bVar3;
  bool bVar4;
  bool bVar5;
  int iVar6;
  DWORD DVar7;
  int extraout_EAX;
  HGLOBAL hMem;
  uint *puVar8;
  char *pcVar9;
  HANDLE input_filehandle;
  uint *puVar10;
  ulonglong uVar11;
  char *pcVar12;
  uint *puVar13;
  LPCSTR pCVar14;
  undefined8 uVar15;
  uint *puVar16;
  longlong lVar17;
  longlong lVar18;
  longlong lVar19;
  LPSTR lpTempFileName;
  HANDLE pvVar20;
  undefined auStackY_6d8 [32];
  int local_690 [2];
  HWND local_688;
  CHAR local_678 [272];
  CHAR local_568 [272];
  WCHAR local_458 [264];
  wchar_t local_248 [264];
  ulonglong local_38;

  local_38 = DAT_140098000 ^ (ulonglong)auStackY_6d8;
  bVar4 = false;
  bVar5 = false;
  bVar2 = false;
  local_688 = param_1;
  hMem = GlobalAlloc(2,0x230);
  if (hMem == (HGLOBAL)0x0) goto LAB_140064a77;
  puVar8 = (uint *)GlobalLock(hMem);
  GetTempPathA(0x104,local_568);
  lpTempFileName = local_678;
  GetTempFileNameA(local_568,"OPWTMP",0,lpTempFileName);
  DVar7 = (DWORD)lpTempFileName;
  pcVar12 = (char *)((longlong)puVar8 + 0x10a);
  lVar18 = 0x106;
  lVar17 = 0x106;
  lVar19 = -(longlong)pcVar12;
  do {
    if ((lVar17 == -0x7ffffef8) || (pcVar12[(longlong)(local_678 + lVar19)] == '\0')) break;
    *pcVar12 = pcVar12[(longlong)(local_678 + lVar19)];
    pcVar12 = pcVar12 + 1;
    lVar17 = lVar17 + -1;
  } while (lVar17 != 0);
  pcVar9 = pcVar12 + -1;
  if (lVar17 != 0) {
    pcVar9 = pcVar12;
  }
  *pcVar9 = '\0';
  input_filehandle = (HANDLE)FUN_14007ef7c(local_678,2);
  *(HANDLE *)(puVar8 + 0x86) = input_filehandle;
  if (input_filehandle == (HANDLE)0xffffffffffffffff) {
LAB_1400649f1:
    iVar6 = 0x2717;
    bVar3 = bVar4;
  }
  else {
    bVar2 = true;
    puVar8[0x89] = 3 - (param_4 != 0);
    puVar8[0x8b] = 0;
    puVar8[0x8a] = 1;
    if (((param_2 == 0) || (param_3 != 0)) && (param_4 == 0)) {
      puVar13 = puVar8 + 1;
      *puVar8 = -(uint)(param_3 != 0) & param_2;
      puVar16 = puVar13;
      do {
        if ((lVar18 == -0x7ffffef8) ||
           (cVar1 = *(char *)(((longlong)maybefilenamestring - (longlong)puVar13) +
                             (longlong)puVar16), cVar1 == '\0')) break;
        *(char *)puVar16 = cVar1;
        puVar16 = (uint *)((longlong)puVar16 + 1);
        lVar18 = lVar18 + -1;
      } while (lVar18 != 0);
      puVar10 = (uint *)((longlong)puVar16 + -1);
      if (lVar18 != 0) {
        puVar10 = puVar16;
      }
      *(char *)puVar10 = '\0';
      input_filehandle = (HANDLE)FUN_14007ef7c(maybefilenamestring,2);
      *(HANDLE *)(puVar8 + 0x84) = input_filehandle;
      bVar3 = true;
      if (input_filehandle == (HANDLE)0xffffffffffffffff) {
        input_filehandle = (HANDLE)FUN_14007ef7c(maybefilenamestring,0);
        *(HANDLE *)(puVar8 + 0x84) = input_filehandle;
        if (input_filehandle == (HANDLE)0xffffffffffffffff) goto LAB_1400649f1;
        puVar8[0x8b] = 1;
      }
      pvVar20 = *(HANDLE *)(puVar8 + 0x86);
      FUN_140062f6c(maybefilenamestring,input_filehandle,1,pvVar20,0);
      iVar6 = extraout_EAX;
      if (extraout_EAX == 0) {
        uVar11 = maybe_process_file((LPCSTR)0x0,*(HANDLE *)(puVar8 + 0x86),puVar8 + 0x88,
                                    (DWORD)pvVar20,local_690);
        iVar6 = (int)uVar11;
        if (iVar6 == 0) {
          *param_6 = puVar8[0x88];
          if (param_3 == 0) {
            FUN_14006296c((char *)puVar13);
          }
          CloseHandle(*(HANDLE *)(puVar8 + 0x84));
          puVar8[0x84] = 0xffffffff;
          puVar8[0x85] = 0xffffffff;
          bVar3 = false;
        }
      }
    }
    else {
      puVar13 = puVar8 + 0x88;
      *puVar8 = param_2;
      iVar6 = check_and_process_maybe(input_filehandle,puVar13,input_filehandle,DVar7);
      bVar3 = bVar5;
      if (iVar6 == 0) {
        *param_6 = *puVar13;
        iVar6 = FUN_14006480c(*puVar13);
        if ((iVar6 == 0) && (param_2 == 0)) {
          puVar13 = puVar8 + 1;
          lVar19 = 0x105;
          lVar17 = (longlong)maybefilenamestring - (longlong)puVar13;
          do {
            if ((lVar19 == -0x7ffffef9) ||
               (cVar1 = *(char *)(lVar17 + (longlong)puVar13), cVar1 == '\0')) break;
            *(char *)puVar13 = cVar1;
            puVar13 = (uint *)((longlong)puVar13 + 1);
            lVar19 = lVar19 + -1;
          } while (lVar19 != 0);
          puVar16 = (uint *)((longlong)puVar13 + -1);
          if (lVar19 != 0) {
            puVar16 = puVar13;
          }
          *(char *)puVar16 = '\0';
          pCVar14 = maybefilenamestring;
          lVar19 = FUN_14007ef7c(maybefilenamestring,2);
          *(longlong *)(puVar8 + 0x84) = lVar19;
          bVar3 = true;
          if (lVar19 == -1) {
            DVar7 = GetLastError();
            if ((DVar7 < 0x21) && ((0x100080020U >> ((ulonglong)DVar7 & 0x3f) & 1) != 0)) {
              MultiByteToWideChar(0,1,maybefilenamestring,-1,local_458,0x105);
              uVar15 = 0x84;
              if (DVar7 != 0x20) {
                uVar15 = 0x86;
              }
              FUN_14007ead4((UINT)uVar15,(va_list)local_458,local_248);
              iVar6 = FUN_140057350(uVar15,local_248,4);
              if (iVar6 == 7) {
                iVar6 = 0x2717;
                bVar3 = bVar4;
              }
              else {
                lVar19 = FUN_14007ef7c(maybefilenamestring,0);
                *(longlong *)(puVar8 + 0x84) = lVar19;
                if (lVar19 == -1) {
                  iVar6 = 0x2717;
                  bVar3 = bVar4;
                }
                else {
                  puVar8[0x8b] = 1;
                  iVar6 = 0;
                }
              }
            }
            else {
              FUN_140068a6c(pCVar14,DVar7);
              iVar6 = -1;
              bVar3 = bVar5;
            }
          }
        }
      }
    }
  }
  if (iVar6 == 0) {
    SetWindowLongPtrA(local_688,0,(LONG_PTR)hMem);
  }
  else {
    if (bVar2) {
      CloseHandle(*(HANDLE *)(puVar8 + 0x86));
    }
    if (bVar3) {
      CloseHandle(*(HANDLE *)(puVar8 + 0x84));
    }
    DeleteFileA(local_678);
    if ((puVar8[0x8b] != 0) && (bVar3)) {
      CloseHandle(*(HANDLE *)(puVar8 + 0x84));
      puVar8[0x84] = 0xffffffff;
      puVar8[0x85] = 0xffffffff;
    }
  }
  GlobalUnlock(hMem);
LAB_140064a77:
  FUN_14008d510(local_38 ^ (ulonglong)auStackY_6d8);
  return;
}

```

My hypothesis is that the checksum calculation is probably not here, but maybe in a call higher up the stack?????

Here is the calling function again:

```

void FUN_140064d78(LPCSTR param_1,uint param_2,undefined8 *param_3)

{
  uint uVar1;
  bool bVar2;
  int iVar3;
  BOOL BVar4;
  undefined4 uVar5;
  undefined8 uVar6;
  char *pcVar7;
  HWND pHVar8;
  HWND pHVar9;
  HGLOBAL pvVar10;
  LPVOID pvVar11;
  HDC hDC;
  int iVar12;
  UINT UVar13;
  char *pcVar14;
  char *pcVar15;
  longlong lVar16;
  uint uVar17;
  ulonglong uVar18;
  uint uVar19;
  bool bVar20;
  undefined auStackY_6b8 [32];
  int local_658;
  HGLOBAL local_650;
  int local_648;
  uint local_644;
  undefined8 *local_640;
  int local_638;
  HWND local_630;
  char *local_628;
  char *local_620;
  HINSTANCE local_618;
  undefined8 local_610;
  undefined8 uStack_608;
  undefined4 local_600;
  undefined8 local_5f8;
  tagRECT local_5f0;
  tagRECT local_5e0;
  WINDOWPLACEMENT local_5d0;
  char local_598 [272];
  char local_488 [272];
  char local_378 [272];
  char local_268 [272];
  char local_158 [272];
  ulonglong local_48;

  local_48 = DAT_140098000 ^ (ulonglong)auStackY_6b8;
  pHVar9 = (HWND)0x0;
  uVar19 = 0;
  iVar12 = 0;
  local_648 = 0;
  local_644 = 0;
  bVar20 = false;
  local_630 = (HWND)0x0;
  local_650 = (HGLOBAL)0x0;
  bVar2 = false;
  *param_3 = 0;
  local_640 = param_3;
  if (param_2 == 0x5d) {
    iVar3 = FUN_14006864c(param_1);
    if (iVar3 == 2) {
      param_2 = 0x5c;
    }
  }
  if ((((param_2 == 0xffffffa5) || (param_2 == 0xfffffffe)) || (param_2 == 2)) ||
     (local_658 = 0, param_2 - 0x5a < 3)) {
    local_658 = 1;
  }
  if ((((param_2 == 0x5a) || (param_2 == 0x5c)) ||
      ((param_2 == 0x5d || ((param_2 == 0x5f || (param_2 == 0x60)))))) || (param_2 == 0x61)) {
    iVar12 = 1;
  }
  else {
    DAT_1400990d4 = 0;
  }
  if ((int)param_2 < 0) {
    iVar12 = 1;
  }
  uVar1 = -param_2;
  if (-1 < (int)param_2) {
    uVar1 = param_2;
  }
  local_638 = iVar12;
  if ((uVar1 != 0x61) && (uVar6 = FUN_14006315c(), (int)uVar6 != 0)) goto LAB_140065729;
  SetCursor(DAT_1400baa28);
  DAT_1400990b8 = 1;
  pHVar8 = pHVar9;
  if ((int)uVar1 < 0x5b) {
    if (((uVar1 == 0x5a) || (uVar1 == 4)) || ((uVar1 == 5 || (uVar1 == 6)))) goto LAB_140064f9c;
    iVar12 = uVar1 - 7;
LAB_140064ebe:
    if ((iVar12 == 0) || (iVar12 == 1)) goto LAB_140064f9c;
    pcVar14 = local_598;
    lVar16 = 0x106;
    do {
      if ((lVar16 == -0x7ffffef8) || (pcVar14[(longlong)param_1 - (longlong)local_598] == '\0'))
      break;
      *pcVar14 = pcVar14[(longlong)param_1 - (longlong)local_598];
      pcVar14 = pcVar14 + 1;
      lVar16 = lVar16 + -1;
    } while (lVar16 != 0);
    pcVar15 = pcVar14 + -1;
    if (lVar16 != 0) {
      pcVar15 = pcVar14;
    }
    *pcVar15 = '\0';
    _splitpath_s(local_598,local_158,0x106,local_488,0x106,local_378,0x106,local_268,0x106);
    lVar16 = 0x106;
    pcVar15 = local_598;
    do {
      if ((lVar16 == -0x7ffffef8) || (pcVar15[0x220] == '\0')) break;
      *pcVar15 = pcVar15[0x220];
      pcVar15 = pcVar15 + 1;
      lVar16 = lVar16 + -1;
    } while (lVar16 != 0);
    pcVar14 = local_268;
    pcVar7 = pcVar15 + -1;
    if (lVar16 != 0) {
      pcVar7 = pcVar15;
    }
    *pcVar7 = '\0';
LAB_140064fe4:
    uVar17 = 0;
    FUN_140021134(local_598,0x106,(longlong)pcVar14);
    uVar5 = 0x1000000;
    local_628 = "OPWDocumentClass";
    local_620 = local_598;
    local_618 = DAT_140099278;
    local_610 = 0x8000000080000000;
    uStack_608 = 0x8000000080000000;
    local_5f8 = 0;
    BVar4 = IsIconic(DAT_140099270);
    if (BVar4 != 0) {
      uVar5 = 0;
      local_5d0.length = 0x2c;
      local_5d0.flags = 0;
      local_5d0.showCmd = 2;
      GetWindowPlacement(DAT_140099270,&local_5d0);
      iVar12 = local_5d0.rcNormalPosition.right - local_5d0.rcNormalPosition.left;
      iVar3 = local_5d0.rcNormalPosition.bottom - local_5d0.rcNormalPosition.top;
      if (0x10 < iVar12) {
        iVar12 = iVar12 + -0x10;
      }
      uStack_608 = CONCAT44(iVar3,iVar12);
      if (0x10 < iVar3) {
        uStack_608 = CONCAT44(iVar3 + -0x10,iVar12);
      }
    }
    local_600 = uVar5;
    SetRect(&local_5f0,0,0,1000,1000);
    if (uVar1 == 0x61) {
LAB_1400650e4:
      pHVar9 = pHVar8;
      if (pHVar8 == (HWND)0x0) {
        pHVar9 = DAT_140099270;
      }
      pHVar9 = CreateWindowExA(0,"OPWChartClass",(LPCSTR)0x0,0x42300000,0,0,local_5f0.right,
                               local_5f0.bottom,pHVar9,(HMENU)0x0,DAT_140099278,(LPVOID)0x0);
      uVar17 = ~-(uint)(pHVar9 != (HWND)0x0) & 0x2714;
      if (pHVar9 == (HWND)0x0) goto LAB_14006522e;
      *local_640 = pHVar9;
      uVar17 = DAT_1400bab40;
      pvVar10 = local_650;
      if (uVar1 != 0x61) {
        if ((uVar1 - 0x5a < 9) && ((0x123U >> (uVar1 - 0x5a & 0x1f) & 1) != 0)) {
          iVar12 = 1;
        }
        else {
          iVar12 = 0;
        }
        uVar17 = maybecreatetemp(pHVar8,uVar19,iVar12,local_658,param_1,(uint *)&local_640);
        if (uVar17 != 0) {
          bVar2 = false;
          goto LAB_140065235;
        }
        uVar17 = (uint)local_640;
      }
      if ((int)uVar1 < 0x5b) {
        if ((((uVar1 == 0x5a) || (uVar1 == 2)) || (uVar1 == 4)) ||
           (((uVar1 == 5 || (uVar1 == 6)) || ((uVar1 == 7 || (uVar1 == 8)))))) {
LAB_1400651dc:
          ShowWindow(pHVar8,0);
          bVar2 = true;
          bVar20 = true;
LAB_140065293:
          uVar17 = FUN_140063ae8(pHVar9,uVar17,uVar1);
          goto LAB_1400652a0;
        }
LAB_140065212:
        uVar17 = FUN_140063370(pHVar9,uVar17,uVar1);
        if (uVar17 != 0) goto LAB_14006522e;
      }
      else {
        if ((uVar1 == 0x5b) || (uVar1 == 0x5c)) goto LAB_1400651dc;
        if (uVar1 != 0x5f) {
          if (uVar1 == 0x60) goto LAB_1400651dc;
          if (uVar1 != 99) goto LAB_140065212;
          bVar2 = false;
          goto LAB_140065293;
        }
        ShowWindow(pHVar8,0);
        bVar2 = true;
        bVar20 = true;
        uVar17 = FUN_140063370(pHVar9,uVar17,0x5f);
LAB_1400652a0:
        if (uVar17 != 0) goto LAB_140065235;
      }
      bVar2 = bVar20;
      pvVar10 = (HGLOBAL)GetWindowLongPtrA(pHVar9,8);
      pvVar11 = GlobalLock(pvVar10);
      if ((*(uint *)((longlong)pvVar11 + 0x22) & 1) != 0) {
        *(uint *)((longlong)pvVar11 + 0x22) = *(uint *)((longlong)pvVar11 + 0x22) ^ 1;
      }
      iVar12 = DAT_1400bac64;
      if ((int)uVar1 < 0x5b) {
        if (((((uVar1 != 0x5a) && (uVar1 != 2)) && (uVar1 != 4)) && ((uVar1 != 5 && (uVar1 != 6)) ))
           && (uVar1 != 7)) {
          bVar20 = uVar1 == 8;
LAB_140065351:
          if (!bVar20) {
            uVar19 = *(uint *)((longlong)pvVar11 + 0xe);
            iVar12 = *(int *)((longlong)pvVar11 + 10);
            if (((uVar1 == 0x5b) || (uVar1 == 0x62)) && ((DAT_1400babf6 & 0x400) != 0)) {
              uVar19 = (uint)(DAT_1400bac64 < 0);
              iVar12 = DAT_1400bac64;
            }
            uVar18 = (ulonglong)*(uint *)((longlong)pvVar11 + 0x5a);
            uVar17 = FUN_14007ede0(pHVar9,*(undefined4 *)((longlong)pvVar11 + 0x56),
                                   *(uint *)((longlong)pvVar11 + 0x5a),iVar12,uVar19);
            if ((uVar1 == 0x62) || (uVar17 = FUN_140055e48(pHVar9,(longlong)pvVar11), uVar17 == 0))
            {
              if ((iVar12 != 0) && ((uVar19 & 1) == 0)) {
                hDC = GetDC(pHVar9);
                FUN_14007ec98(hDC,iVar12);
                ReleaseDC(pHVar9,hDC);
                local_648 = iVar12;
              }
              local_644 = uVar19 & 1;
              if (uVar17 == 0) {
                GetClientRect(pHVar9,&local_5e0);
                FUN_14007ee90(pHVar9,0,uVar18,*(int *)((longlong)pvVar11 + 2),local_5e0.right,0);
                FUN_14007ee90(pHVar9,1,uVar18,*(int *)((longlong)pvVar11 + 6),local_5e0.bottom,0) ;
                SendMessageA(pHVar9,0x114,(ulonglong)*(ushort *)((longlong)pvVar11 + 2) << 0x10 |  99
                             ,0);
                SendMessageA(pHVar9,0x115,(ulonglong)*(ushort *)((longlong)pvVar11 + 6) << 0x10 |  99
                             ,0);
              }
            }
            goto LAB_140065489;
          }
        }
LAB_1400654bb:
        if ((DAT_1400babf6 & 0x400) == 0) {
          iVar12 = 0;
        }
        else if (uVar1 - 0x5a < 2) {
          if ((DAT_1400bac64 < 500) && (DAT_1400bac64 != 0)) {
            uVar5 = 1;
          }
          else {
            uVar5 = 0;
          }
          *(undefined4 *)((longlong)pvVar11 + 0xe) = uVar5;
          *(int *)((longlong)pvVar11 + 10) = iVar12;
        }
        uVar17 = FUN_14007ede0(pHVar9,*(undefined4 *)((longlong)pvVar11 + 0x56),
                               *(undefined4 *)((longlong)pvVar11 + 0x5a),iVar12,0);
        local_648 = 0;
        if (1 < iVar12 + 1U) {
          local_648 = iVar12;
        }
      }
      else {
        if (((uVar1 == 0x5b) || (uVar1 == 0x5c)) || ((uVar1 == 0x5f || (uVar1 == 0x60))))
        goto LAB_1400654bb;
        if (uVar1 != 0x61) {
          bVar20 = uVar1 == 99;
          goto LAB_140065351;
        }
        uVar17 = FUN_14007ede0(pHVar9,*(undefined4 *)((longlong)pvVar11 + 0x56),
                               *(undefined4 *)((longlong)pvVar11 + 0x5a),0,0);
      }
LAB_140065489:
      GlobalUnlock(pvVar10);
      pHVar8 = local_630;
    }
    else {
      pHVar8 = (HWND)SendMessageA(DAT_1400992a8,0x220,0,(LPARAM)&local_628);
      local_630 = pHVar8;
      if (pHVar8 == (HWND)0x0) {
        uVar17 = 0x2712;
      }
      else {
        GetClientRect(pHVar8,&local_5f0);
      }
      pvVar10 = (HGLOBAL)0x0;
      pHVar9 = (HWND)0x0;
      if (uVar17 == 0) goto LAB_1400650e4;
    }
  }
  else {
    if (((uVar1 != 0x5b) && (uVar1 != 0x5f)) && (uVar1 != 0x60)) {
      iVar12 = uVar1 - 0x62;
      goto LAB_140064ebe;
    }
LAB_140064f9c:
    uVar17 = FUN_14007ea70(500,local_598);
    if (uVar17 == 0) {
      uVar19 = DAT_140099140 + 1;
      FUN_140068b2c(local_488,0x106,&DAT_1400901ec,(ulonglong)uVar19);
      pcVar14 = local_488;
      goto LAB_140064fe4;
    }
LAB_14006522e:
    bVar2 = false;
    pvVar10 = (HGLOBAL)0x0;
  }
LAB_140065235:
  if (uVar17 == 0) {
    if (((((uVar1 == 4) || (uVar1 == 5)) || (uVar1 == 6)) ||
        (((uVar1 == 7 || (uVar1 == 8)) || ((uVar1 == 0x5b || ((uVar1 == 0x60 || (uVar1 == 0x62)) ))))
        )) || (uVar1 == 99)) {
      DAT_140099140 = DAT_140099140 + 1;
    }
    if (uVar1 == 0x61) goto LAB_140065729;
    if (((((uVar1 - 0x5d & 0xfffffffc) != 0) || (uVar1 == 0x5e)) && (!bVar2)) &&
       ((uVar1 - 0x5a & 0xfffffffd) != 0)) {
      ShowWindow(pHVar8,5);
      ShowWindow(pHVar9,5);
    }
    if (local_648 != 0) {
      FUN_1400690ec(pHVar9,local_648,local_644);
    }
    FUN_14006909c(pHVar8);
    FUN_14005a940(pHVar8,1);
    iVar12 = 0;
    if (uVar1 == 0x5a) {
LAB_1400656a2:
      FUN_140025c0c(pHVar9,0,0,1,0,0);
      FUN_140026c90(pHVar9,0x459,0,0,1,0);
      pvVar11 = GlobalLock(pvVar10);
      if (*(HGLOBAL *)((longlong)pvVar11 + 0xfe) != (HGLOBAL)0x0) {
        FUN_140043d1c(*(HGLOBAL *)((longlong)pvVar11 + 0xfe),0,iVar12,1,0);
      }
    }
    else {
      if (uVar1 != 0x5b) {
        iVar12 = 0;
        if ((uVar1 != 0x5f) && (uVar1 != 0x60)) {
          if (uVar1 == 0x62) goto LAB_140065753;
          if (uVar1 != 99) goto LAB_140065713;
          iVar12 = 1;
        }
        goto LAB_1400656a2;
      }
LAB_140065753:
      pvVar11 = GlobalLock(pvVar10);
      *(uint *)((longlong)pvVar11 + 0x22) = *(uint *)((longlong)pvVar11 + 0x22) | 0x80;
      FUN_140026c90(pHVar9,0x457,(uint)*(ushort *)((longlong)pvVar11 + 0xf6) << 0x10,0,1,0);
      FUN_140025c0c(pHVar9,0,0,1,0,0);
      if ((*(uint *)((longlong)pvVar11 + 0x22) & 0x80) != 0) {
        *(uint *)((longlong)pvVar11 + 0x22) = *(uint *)((longlong)pvVar11 + 0x22) ^ 0x80;
      }
      iVar12 = GetScrollPos(pHVar9,0);
      *(int *)((longlong)pvVar11 + 2) = iVar12;
      iVar12 = GetScrollPos(pHVar9,1);
      *(int *)((longlong)pvVar11 + 6) = iVar12;
    }
    GlobalUnlock(pvVar10);
  }
  else {
    if (pHVar8 == (HWND)0x0) {
      if (pHVar9 != (HWND)0x0) {
        DefWindowProcA(pHVar9,0x10,0,0);
      }
    }
    else {
      FUN_140067690(pHVar8);
      DefMDIChildProcA(pHVar8,0x10,0,0);
    }
    if (((uVar17 != 2) && (local_638 == 0)) && (uVar17 != 0xffffffff)) {
      UVar13 = 7;
      if (uVar17 == 7) {
        UVar13 = 0x5dd;
      }
      else if (uVar17 == 0x2716) {
        UVar13 = 0x33;
      }
      else if (uVar17 == 0x2717) {
        UVar13 = 0x3a;
      }
      else if (uVar17 == 0x2718) {
        UVar13 = (-(uint)(local_658 != 0) & 0x54c) + 0x98;
      }
      FUN_14005738c(UVar13);
    }
  }
LAB_140065713:
  SetCursor(DAT_1400baa20);
  DAT_1400990b8 = 0;
LAB_140065729:
  FUN_14008d510(local_48 ^ (ulonglong)auStackY_6b8);
  return;
}

```

now I am like 95% sure that the checksum check happens in this function somehow. Maybe just set a breakpoint to after the temp file creation and see what happens???

Ok, so we did NOT go to this thing here:

```

        if (uVar17 != 0) {
          bVar2 = false;
          goto LAB_140065235;
        }

```

so the checksum checking or whatever wasn't there...

Ok, so we also do not jump here:

```
if (uVar17 != 0) goto LAB_140065235;
```

We call GetWindowLongPtrA so I guess that is a good sign..

We never reach this check here for the number two:

```

       14006534e 83  f9  02       CMP        param_1 ,0x2
                             LAB_140065351                                   XREF[1]:     14006531d (j)
       140065351 0f  84  64       JZ         LAB_1400654bb
                 01  00  00


```

We actually DO pass the
```
if ((int)uVar1 < 0x5b) {
```

check in both valid and invalid files, therefore let's keep digging.

This check here:

```

        else if (uVar1 - 0x5a < 2) {
          if ((DAT_1400bac64 < 500) && (DAT_1400bac64 != 0)) {
            uVar5 = 1;
          }
          else {
            uVar5 = 0;
          }
          *(undefined4 *)((longlong)pvVar11 + 0xe) = uVar5;
          *(int *)((longlong)pvVar11 + 10) = iVar12;
        }

```

is never reached in valid or invalid files...

We always go through this case here:

```

        if ((DAT_1400babf6 & 0x400) == 0) {
          iVar12 = 0;
        }

```

we should end up in the:

```

LAB_140065489:
      GlobalUnlock(pvVar10);
      pHVar8 = local_630;

```

We never go to the ShowWindow calls here:

```

    if (((((uVar1 - 0x5d & 0xfffffffc) != 0) || (uVar1 == 0x5e)) && (!bVar2)) &&
       ((uVar1 - 0x5a & 0xfffffffd) != 0)) {
      ShowWindow(pHVar8,5);
      ShowWindow(pHVar9,5);
    }

```

we never go here:

```

    if (local_648 != 0) {
      FUN_1400690ec(pHVar9,local_648,local_644);
    }

```

This here may be actually the fail thing:

```

      if (uVar1 != 0x5b) {
        iVar12 = 0;
        if ((uVar1 != 0x5f) && (uVar1 != 0x60)) {
          if (uVar1 == 0x62) goto LAB_140065753;
          if (uVar1 != 99) goto LAB_140065713;
          iVar12 = 1;
        }
        goto LAB_1400656a2;
      }

```

The fucking error doesn't even appear inside that function. So all of that analysis was wrong maybe???

Here is the calling function (again):

```


int FUN_140065ad8(LPCSTR param_1,uint param_2)

{
  int *piVar1;
  int iVar2;
  uint uVar3;
  HWND pHVar4;
  ulonglong uVar5;
  HGLOBAL hMem;
  LPVOID pvVar6;
  int iVar7;
  int iVar8;
  HWND local_res18 [2];

  iVar2 = 0;
  SetCursor(DAT_1400baa28);
  iVar8 = 1;
  DAT_1400990b8 = 1;
  pHVar4 = FUN_1400657f0(param_1);
  if (pHVar4 == (HWND)0x0) {
    if (param_2 == 0x5d) {
      param_2 = 0xfffffffd;
      iVar7 = iVar8;
    }
    else {
      iVar7 = 0;
      if (param_2 == 0x5c) {
        param_2 = 0xfffffffe;
        iVar7 = iVar8;
      }
    }
    iVar2 = openfileastempandopenwindows(param_1,param_2,local_res18);
    if (local_res18[0] == (HWND)0x0) {
      iVar2 = iVar8;
    }
    if (iVar2 != 0) goto LAB_140065c1c;
    if (((param_2 == 0xfffffffe) || (param_2 == 2)) || (param_2 - 0x5b < 2)) {
      uVar5 = FUN_1400658c0(local_res18[0],param_1,param_2);
      iVar2 = (int)uVar5;
      if (iVar2 != 0) goto LAB_140065c1c;
    }
    if (((iVar7 != 0) && (local_res18[0] != (HWND)0x0)) &&
       (hMem = (HGLOBAL)GetWindowLongPtrA(local_res18[0],8), hMem != (HGLOBAL)0x0)) {
      pvVar6 = GlobalLock(hMem);
      piVar1 = *(int **)((longlong)pvVar6 + 0x2ca);
      if (((piVar1 != (int *)0x0) && (*piVar1 != 0)) && (*(longlong *)(piVar1 + 3) != 0)) {
        *(undefined4 *)(*(longlong *)(piVar1 + 3) + 0x60) = 2;
      }
      GlobalUnlock(hMem);
    }
  }
  else {
    BringWindowToTop(pHVar4);
  }
  if (DAT_1400991b0 != (HWND)0x0) {
    uVar3 = FUN_140065a10(DAT_1400991b0);
    if (uVar3 == 0) {
      pHVar4 = GetParent(DAT_1400991b0);
      SendMessageA(pHVar4,0x10,0,0);
    }
    DAT_1400991b0 = (HWND)0x0;
  }
LAB_140065c1c:
  SetCursor(DAT_1400baa20);
  DAT_1400990b8 = 0;
  return iVar2;
}


```

the openfileastempandopenwindows is the function thing...

The:

```

  else {
    BringWindowToTop(pHVar4);
  }

```

was never triggered. Neither on valid or invalid...

```

  if (DAT_1400991b0 != (HWND)0x0) {
    uVar3 = FUN_140065a10(DAT_1400991b0);
    if (uVar3 == 0) {
      pHVar4 = GetParent(DAT_1400991b0);
      SendMessageA(pHVar4,0x10,0,0);
    }
    DAT_1400991b0 = (HWND)0x0;
  }

```

We actually never reach this with the invalid file. We always reach this with the valid file...

Here:

```

    if (((param_2 == 0xfffffffe) || (param_2 == 2)) || (param_2 - 0x5b < 2)) {
      uVar5 = FUN_1400658c0(local_res18[0],param_1,param_2);
      iVar2 = (int)uVar5;
      if (iVar2 != 0) goto LAB_140065c1c;
    }

```

The function there is actually the fail function maybe...

Yeah, the `FUN_1400658c0(local_res18[0],param_1,param_2);` call is the check call.

Here is the check function:

```

ulonglong checkvaliddatathing(HWND param_1,LPCSTR param_2,int param_3)

{
  int iVar1;
  BOOL BVar2;
  ulonglong uVar3;
  HWND pHVar4;
  HGLOBAL hMem;
  int *piVar5;
  uint uVar6;

  if ((param_3 - 0x5aU < 2) || (param_3 == -0x5b)) {
    uVar6 = 1;
  }
  else {
    uVar6 = 0;
  }
  iVar1 = -param_3;
  if (-1 < param_3) {
    iVar1 = param_3;
  }
  uVar3 = FUN_14004e2dc(param_1,param_2,(uint)(param_3 == 0x5b),
                        (uint)((iVar1 - 0x5aU & 0xfffffffd) != 0),(uint)(param_3 != -0x5b),uVar6) ;
  if ((int)uVar3 == 0) {
    pHVar4 = GetParent(param_1);
    BVar2 = IsWindowVisible(pHVar4);
    if ((BVar2 == 0) && (param_3 != 0x5c)) {
      pHVar4 = GetParent(param_1);
      ShowWindow(pHVar4,5);
      pHVar4 = GetParent(param_1);
      SendMessageA(pHVar4,6,1,1);
      pHVar4 = GetParent(param_1);
      FUN_14005a84c(pHVar4);
    }
    pHVar4 = GetParent(param_1);
    hMem = (HGLOBAL)GetWindowLongPtrA(pHVar4,0);
    piVar5 = (int *)GlobalLock(hMem);
    if (*piVar5 == 0) {
      FUN_140066038((char *)(piVar5 + 1));
    }
    GlobalUnlock(hMem);
  }
  else {
    pHVar4 = GetParent(param_1);
    if (param_3 != 0x5c) {
      FUN_140067690(pHVar4);
      DefMDIChildProcA(pHVar4,0x10,0,0);
    }
  }
  return uVar3 & 0xffffffff;
}
```

the checking happens before this:

```

  if ((int)uVar3 == 0) {
    pHVar4 = GetParent(param_1);
    BVar2 = IsWindowVisible(pHVar4);

```

the actual checking happens inside this function here:

```

  uVar3 = FUN_14004e2dc(param_1,param_2,(uint)(param_3 == 0x5b),
                        (uint)((iVar1 - 0x5aU & 0xfffffffd) != 0),(uint)(param_3 != -0x5b),uVar6) ;

```

i am going to call it `check_buffer_check`.

Here is the signature:

```

ulonglong check_buffer_check(HWND param_1,LPCSTR param_2,int param_3,int param_4,int param_5,
                            uint param_6)

```

so I think that param_1 is the filehandle here.


Here is some stuff:

```

  uVar3 = check_buffer_check(window_handle,filename,(uint)(some_integer == 0x5b),
                             (uint)((iVar1 - 0x5aU & 0xfffffffd) != 0),(uint)(some_integer != -0x 5b)
                             ,uVar6);

```

check_buffer_check

Here is the bullshit:

```

ulonglong check_buffer_check(HWND window_handle,LPCSTR original_filename,int param_3,int param_4 ,
                            int param_5,uint param_6)

{
  undefined8 *puVar1;
  uint extraout_EAX;
  uint *window_lock;
  ulonglong uVar2;
  undefined8 uVar3;
  LPVOID pvVar4;
  HWND pHVar5;
  HGLOBAL hMem;
  int *piVar6;
  undefined4 *puVar7;
  undefined *puVar8;
  uint *puVar9;
  uint return_value;
  uint uVar10;
  int iVar11;
  UINT UVar12;
  int iVar13;
  uint *opened_file;
  longlong lVar14;
  int iVar15;
  int local_58;
  uint local_54;
  HGLOBAL local_50;
  HGLOBAL local_48;

  opened_file = (uint *)0xffffffffffffffff;
  local_54 = 0;
  DAT_140099090 = (HGLOBAL)0x0;
  iVar13 = 1;
  DAT_14009908c = 0;
  local_58 = 1;
  DAT_1400980b4 = 1;
  DAT_140099088 = 0;
  DAT_140099078 = (HGLOBAL)0x0;
  DAT_140099070 = 0;
  DAT_14009906c = 0;
  DAT_1400990a0 = 0;
  if ((param_6 == 0) || (DAT_140099068 = iVar13, (DAT_1400babf6 & 0x400) == 0)) {
    DAT_140099068 = 0;
  }
  SetCursor(DAT_1400baa28);
  puVar8 = &DAT_00000008;
  some_thing_global = 1;
  local_48 = (HGLOBAL)GetWindowLongPtrA(window_handle,8);
  if (local_48 == (HGLOBAL)0x0) {
    return 1;
  }
  window_lock = (uint *)GlobalLock(local_48);
  *(undefined4 *)((longlong)window_lock + 0x56) = 5000;
  *(undefined4 *)((longlong)window_lock + 0x5a) = 5000;
  *(undefined4 *)((longlong)window_lock + 0x9a) = 10;
  *(undefined4 *)((longlong)window_lock + 0x9e) = 10;
  uVar2 = FUN_140042714((longlong)window_lock,puVar8,*(int *)((longlong)window_lock + 0xf6));
  return_value = (uint)uVar2;
  iVar11 = iVar13;
  if (return_value == 0) {
    puVar7 = &DAT_1400bb404;
    do {
      puVar7[-1] = (int)uVar2;
      return_value = (int)uVar2 + 1;
      uVar2 = (ulonglong)return_value;
      *puVar7 = 5;
      puVar7 = puVar7 + 2;
    } while ((int)return_value < 0x1e);
    puVar1 = (undefined8 *)((longlong)window_lock + 0x1da);
    uVar3 = FUN_1400470e4(*(uint *)((longlong)window_lock + 0x26),100,0x68,puVar1);
    return_value = (uint)uVar3;
    if (return_value == 0) {
      pvVar4 = GlobalLock((HGLOBAL)*puVar1);
      *(undefined8 *)((longlong)pvVar4 + 0x10) = 0;
      *(undefined8 *)((longlong)pvVar4 + 0x20) = 0;
      *(undefined4 *)((longlong)pvVar4 + 0x28) = 0;
      *(undefined8 *)((longlong)pvVar4 + 0x34) = 0;
      FUN_140048a3c((HGLOBAL)*puVar1);
      GlobalUnlock((HGLOBAL)*puVar1);
      uVar2 = FUN_140049608(*(uint *)((longlong)window_lock + 0x26),0x67);
      return_value = (uint)uVar2;
      if (return_value == 0) {
        uVar2 = FUN_140049608(*(uint *)((longlong)window_lock + 0x26),0x68);
        return_value = (uint)uVar2;
        if (return_value == 0) {
          uVar2 = FUN_140049608(*(uint *)((longlong)window_lock + 0x26),0x65);
          if ((int)uVar2 != 0) {
            return uVar2;
          }
          uVar2 = FUN_140049608(*(uint *)((longlong)window_lock + 0x26),0x66);
          if ((int)uVar2 != 0) {
            return uVar2;
          }
          DAT_140099078 = GlobalAlloc(0x42,29000);
          return_value = ~-(uint)(DAT_140099078 != (HGLOBAL)0x0) & 0x2714;
          if (DAT_140099078 != (HGLOBAL)0x0) {
            DAT_140099080 = GlobalLock(DAT_140099078);
            pHVar5 = GetParent(window_handle);
            hMem = (HGLOBAL)GetWindowLongPtrA(pHVar5,0);
            iVar15 = iVar13;
            if (hMem != (HGLOBAL)0x0) {
              piVar6 = (int *)GlobalLock(hMem);
              if ((*piVar6 == 0) &&
                 (puVar9 = *(uint **)(piVar6 + 0x84), puVar9 != (uint *)0xffffffffffffffff)) {
                SetFilePointer(puVar9,0,(PLONG)0x0,0);
                local_58 = 0;
                opened_file = puVar9;
                iVar15 = 0;
              }
              GlobalUnlock(hMem);
            }
            iVar11 = local_58;
            if ((iVar15 == 0) ||
               (opened_file = (uint *)create_file_bullshit(original_filename,0),
               opened_file != (uint *)0xffffffffffffffff)) {
              return_value = FUN_14004e904(opened_file);
              iVar15 = iVar13;
              if (return_value == 0) {
                do {
                  puVar9 = &local_54;
                  return_value = FUN_14005333c(opened_file,puVar9,&param_6);
                  if (return_value != 0) goto LAB_14004e55f;
                  if (local_54 == 0x4003) {
                    if (iVar13 != 0) {
                      return_value = 0x5dd;
                      goto LAB_14004e55f;
                    }
                    if (iVar15 != 0) {
                      puVar9 = window_lock;
                      return_value = FUN_14004ee84(window_handle,(longlong)window_lock,opened_fil e);
                    }
                    iVar15 = 0;
LAB_14004e655:
                    if (return_value != 0) goto LAB_14004e55f;
                  }
                  else if (local_54 == 0x4005) {
                    puVar9 = opened_file;
                    return_value = FUN_14004eb64((longlong)window_lock,opened_file);
                    iVar13 = 0;
                    goto LAB_14004e655;
                  }
                } while (local_54 != 0x6001);
                if (hMem != (HGLOBAL)0x0) {
                  pvVar4 = GlobalLock(hMem);
                  *(uint *)((longlong)pvVar4 + 0x228) = (uint)(DAT_1400980b4 == 0);
                  GlobalUnlock(hMem);
                }
                if (param_3 != 0) {
                  uVar2 = FUN_140061b80((longlong)window_lock,puVar9,1);
                  return_value = (uint)uVar2;
                  if (return_value != 0) goto LAB_14004e55f;
                  uVar2 = FUN_140049480(*(uint *)((longlong)window_lock + 0x26),0x66,(int *)&para m_6
                                       );
                  return_value = (uint)uVar2;
                  if (return_value != 0) goto LAB_14004e55f;
                  iVar13 = 0;
                  if (0 < (int)param_6) {
                    do {
                      uVar2 = FUN_14004952c(*(uint *)((longlong)window_lock + 0x26),0x66,iVar13,
                                            (int *)&local_54);
                      return_value = (uint)uVar2;
                      if ((return_value != 0) ||
                         (return_value = FUN_140047020(*(uint *)((longlong)window_lock + 0x26),0x 66,
                                                       local_54,&local_50), return_value != 0))
                      goto LAB_14004e55f;
                      uVar10 = 0;
                      do {
                        piVar6 = (int *)FUN_14007ac74(local_50,uVar10);
                        if ((((piVar6 != (int *)0x0) && (*piVar6 == 1)) &&
                            (lVar14 = (longlong)piVar6[2],
                            -1 < *(int *)(lVar14 + 0x58 + (longlong)piVar6))) &&
                           (iVar15 = 0, 0 < *(int *)(lVar14 + 0x5c + (longlong)piVar6))) {
                          do {
                            FUN_140045870(*(uint *)((longlong)window_lock + 0x26),-1,
                                          *(int *)(lVar14 + 0x54 + (longlong)piVar6),
                                          *(int *)(lVar14 + 0x58 + (longlong)piVar6) + iVar15);
                            return_value = extraout_EAX;
                            if (extraout_EAX != 0) goto LAB_14004e55f;
                            iVar15 = iVar15 + 1;
                          } while (iVar15 < *(int *)(lVar14 + 0x5c + (longlong)piVar6));
                        }
                        GlobalUnlock(local_50);
                        uVar10 = uVar10 + 1;
                      } while ((int)uVar10 < 0x1e);
                      FUN_140048a3c(local_50);
                      iVar13 = iVar13 + 1;
                    } while (iVar13 < (int)param_6);
                  }
                }
                FUN_14003e2c4(window_handle,(longlong)window_lock,0x6c,0xffffffff,1);
                FUN_14003e2c4(window_handle,(longlong)window_lock,0x6a,0xffffffff,0);
                FUN_14003e2c4(window_handle,(longlong)window_lock,0x6e,0xffffffff,0);
              }
            }
            else {
              return_value = 0x2713;
            }
          }
        }
      }
    }
  }
LAB_14004e55f:
  if (DAT_140099090 != (HGLOBAL)0x0) {
    GlobalUnlock(DAT_140099090);
    GlobalFree(DAT_140099090);
    DAT_140099090 = (HGLOBAL)0x0;
  }
  if ((iVar11 != 0) && (opened_file != (uint *)0xffffffffffffffff)) {
    CloseHandle(opened_file);
  }
  if (return_value == 0) {
    if (DAT_1400980b4 == 0) {
      FUN_1400571b0((longlong)window_lock);
    }
    return_value = FUN_140053960(window_handle,(longlong)window_lock,param_4);
    if (return_value == 0) {
      if (DAT_1400980b4 != 0) {
        return_value = FUN_140055e48(window_handle,(longlong)window_lock);
      }
    }
    else if (return_value != 0xffffffff) {
      return_value = 0x5e3;
    }
  }
  if (DAT_140099078 != (HGLOBAL)0x0) {
    GlobalUnlock(DAT_140099078);
    GlobalFree(DAT_140099078);
    DAT_140099078 = (HGLOBAL)0x0;
  }
  if (return_value != 0) {
    UVar12 = return_value;
    if (0x31 < return_value - 0x5dd) {
      if (return_value == 0xffffffff) {
        UVar12 = 0;
      }
      else {
        UVar12 = 0x60;
        if (return_value != 0x67) {
          UVar12 = 7;
        }
      }
    }
    pHVar5 = GetParent(window_handle);
    ShowWindow(pHVar5,0);
    if ((UVar12 != 0) && (param_5 != 0)) {
      FUN_14005738c(UVar12);
    }
  }
  if ((*(uint *)((longlong)window_lock + 0x22) & 1) != 0) {
    *(uint *)((longlong)window_lock + 0x22) = *(uint *)((longlong)window_lock + 0x22) ^ 1;
  }
  GlobalUnlock(local_48);
  FUN_14007a020(2,0);
  SetCursor(DAT_1400baa20);
  some_thing_global = 0;
  return (ulonglong)return_value;
}

```

Oh look at that!!!! We found the function which checks the CRC of the file:

```


void FUN_14004e904(HANDLE file_handle)

{
  DWORD DVar1;
  int iVar2;
  LSTATUS LVar3;
  BOOL BVar4;
  ulonglong uVar5;
  undefined auStackY_e8 [32];
  DWORD local_b8;
  uint local_b4;
  int local_b0 [4];
  HKEY local_a0;
  uint local_98 [4];
  CHAR local_88 [4];
  undefined local_84;
  ulonglong local_28;

  local_28 = DAT_140098000 ^ (ulonglong)auStackY_e8;
  local_a0 = (HKEY)0x0;
  local_b0[0] = 0;
  local_b0[2] = 0;
  local_b0[1] = 4;
  iVar2 = lstrlenA("UOCF");
  local_b8 = FUN_1400533e8(file_handle,(longlong)iVar2,local_88,0x52);
  if (local_b8 == 0) {
    local_84 = 0;
    iVar2 = lstrcmpiA("UOCF",local_88);
    if (iVar2 != 0) {
      local_b8 = 0x5dd;
    }
    if (local_b8 == 0) {
      LVar3 = RegOpenKeyExA((HKEY)0xffffffff80000001,"Software\\Microsoft\\Office\\16.0\\Common" ,0,
                            0x20019,&local_a0);
      if (LVar3 == 0) {
        RegQueryValueExA(local_a0,"OrgchartSkipCRC",(LPDWORD)0x0,(LPDWORD)(local_b0 + 2),
                         (LPBYTE)local_b0,(LPDWORD)(local_b0 + 1));
        RegCloseKey(local_a0);
      }
      if ((local_b0[0] != 0) || (uVar5 = FUN_140055144(file_handle), (int)uVar5 == 0)) {
        DAT_140099090 = GlobalAlloc(2,0xfffe);
        local_b8 = ~-(uint)(DAT_140099090 != (HGLOBAL)0x0) & 0x2714;
        if (DAT_140099090 != (HGLOBAL)0x0) {
          DAT_140099098 = GlobalLock(DAT_140099090);
          DAT_140099088 = SetFilePointer(file_handle,0,(PLONG)0x0,1);
          DAT_14009908c = 0;
          BVar4 = ReadFile(file_handle,DAT_140099098,0xfffe,&local_b8,(LPOVERLAPPED)0x0);
          if (BVar4 != 0) {
            local_b4 = 0;
            DVar1 = local_b8;
            do {
              local_b8 = DVar1;
              local_b8 = FUN_14005333c(file_handle,&local_b4,local_98);
              if (local_b8 != 0) break;
              if (local_b4 == 1) {
                if ((ushort)DAT_1400a97b2 != 0) break;
              }
              else if (local_b4 == 2) {
                DAT_1400980b4 = (uint)((ushort)DAT_1400a97b2 != 4);
              }
              else if ((local_b4 == 3) && (0x3e9 < (ushort)DAT_1400a97b2)) break;
              DVar1 = 0;
            } while (local_b4 != 0x4002);
          }
        }
      }
    }
  }
  FUN_14008d510(local_28 ^ (ulonglong)auStackY_e8);
  return;
}

```

Here is the `void filehandle_crc_check(HANDLE file_handle)`

So we can just set the registry key OrgchartSkipCRC to skip the file check completely. That's neat!

This blog post here: https://hackmag.com/security/winafl/ was of great help in dealing with the bullshit here....


000000E7356FE138  000000E7356FE1C0   "C:\\Users\\elsku\\AppData\\Local\\Temp\\OPW410E.tmp"


Looking at the temporary file here:

```

00000000: 02 00 ff ff 00 00 00 00 00 00 fe 61 f9 7f 00 00  ...........a....
00000010: 60 28 06 00 00 00 f4 7e 00 00 00 00 ff ff c0 0d  `(.....~........
00000020: 00 00 12 00 00 00 00 00 00 00 00 00 00 00 fe ff  ................
00000030: 00 0e 00 00 12 00 00 00 00 00 00 00 00 00 00 00  ................
00000040: fd ff 00 01 00 00 9c 0c 00 00 00 00 00 00 00 00  ................
00000050: 00 00 6f 35 e7 00 00 00 03 00 00 00 00 00 00 00  ..o5............
00000060: 70 28 76 6d 9a 02 00 00 03 00 00 00 00 00 00 00  p(vm............
00000070: b4 0b 00 00 00 00 00 00 e2 9e 52 5f f9 7f 00 00  ..........R_....
00000080: d0 e0 6f 35 e7 00 00 00 5a 00 00 00 9a 02 00 00  ..o5....Z.......
00000090: 01 e1 6f 35 e7 00 00 00 00 00 00 00 00 00 00 00  ..o5............
000000a0: e0 e0 6f 35 e7 00 00 00 00 00 00 00 f9 7f 00 00  ..o5............
000000b0: 0e 41 00 00 00 00 00 00 37 e9 fb 61 f9 7f 00 00  .A......7..a....
000000c0: b4 0b 00 00 00 00 00 00 c0 e1 6f 35 e7 00 00 00  ..........o5....
000000d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000000e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000000f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000100: fd ff fc ff 00 00 00 01 00 00 9c 0c 00 00 00 00  ................
00000110: c8 00 00 00 00 00 00 00 40 0e 00 00 00 26 00 00  ........@....&..
00000120: 40 00 00 00 c0 0d 00 00 40 00 00 00 c0 27 00 00  @.......@....'..
00000130: c0 00 00 00 00 23 00 00 c0 00 00 00 c0 24 00 00  .....#.......$..
00000140: c0 00 00 00 40 2b 00 00 00 05 00 00 37 00 34 00  ....@+......7.4.
00000150: 2d 00 31 00 30 00 30 00 f7 00 00 f7 71 6d 1f 00  -.1.0.0.....qm..
00000160: 40 a2 92 6d 9a 02 00 00 e0 d5 8f 6d 9a 02 00 00  @..m.......m....
00000170: 70 00 78 00 00 00 6d 00 46 00 69 00 6c 00 65 00  p.x...m.F.i.l.e.
00000180: 41 00 73 00 73 00 6f 00 63 00 69 00 61 00 74 00  A.s.s.o.c.i.a.t.
00000190: 69 00 6f 00 6e 00 73 00 5c 00 2e 00 6f 00 70 00  i.o.n.s.\...o.p.
000001a0: 78 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  x...............
000001b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000001c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000001d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000001e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000001f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000200: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000210: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000220: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000230: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000240: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000250: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000260: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000270: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000280: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000290: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000002a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000002b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000002c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000002d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000002e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000002f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000300: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000310: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000320: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000330: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000340: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000350: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000360: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000370: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000380: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000390: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000003a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000003b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000003c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000003d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000003e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000003f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000400: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000410: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000420: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000430: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000440: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000450: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000460: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000470: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000480: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000490: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000004a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000004b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000004c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000004d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000004e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000004f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000500: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000510: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000520: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000530: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000540: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000550: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000560: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000570: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000580: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000590: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000005a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000005b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000005c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000005d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000005e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000005f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000600: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000610: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000620: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000630: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000640: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000650: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000660: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000670: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000680: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000690: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000006a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000006b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000006c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000006d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000006e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000006f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000700: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000710: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000720: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000730: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000740: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000750: 00 00 00 00 00 00 00 00 00 00 00 00 c0 0d 00 00  ................
00000760: 40 00 00 00 00 23 00 00 c0 00 00 00 c0 24 00 00  @....#.......$..
00000770: c0 00 00 00 00 26 00 00 40 00 00 00 c0 27 00 00  .....&..@....'..
00000780: c0 00 00 00 40 2b 00 00 00 05 00 00 00 00 00 00  ....@+..........
00000790: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000007a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000007b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000007c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000007d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000007e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000007f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000800: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000810: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000820: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000830: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000840: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000850: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000860: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000870: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000880: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000890: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000008a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000008b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000008c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000008d0: 00 00 00 00 00 00 00 00 7f 00 00 7f f6 6c 1f 00  .............l..
000008e0: 20 99 bd 6a 9a 02 00 00 00 1e 91 6d 9a 02 00 00   ..j.......m....
000008f0: 62 00 66 00 2d 00 31 00 7d 00 00 7d f4 6c 1f 00  b.f.-.1.}..}.l..
00000900: 10 6e 9a 6d 9a 02 00 00 00 1e 91 6d 9a 02 00 00  .n.m.......m....
00000910: 30 00 63 00 39 00 31 00 65 00 66 00 62 00 38 00  0.c.9.1.e.f.b.8.
00000920: 62 00 7d 00 23 00 7b 00 35 00 33 00 66 00 35 00  b.}.#.{.5.3.f.5.
00000930: 36 00 33 00 30 00 64 00 2d 00 62 00 36 00 62 00  6.3.0.d.-.b.6.b.
00000940: 66 00 2d 00 31 00 31 00 64 00 30 00 2d 00 39 00  f.-.1.1.d.0.-.9.
00000950: 34 00 66 00 32 00 2d 00 30 00 30 00 61 00 30 00  4.f.2.-.0.0.a.0.
00000960: 63 00 39 00 31 00 65 00 66 00 62 00 38 00 62 00  c.9.1.e.f.b.8.b.
00000970: 7d 00 00 00 5c 00 5c 00 3f 00 5c 00 53 00 54 00  }...\.\.?.\.S.T.
00000980: 4f 00 52 00 41 00 47 00 45 00 23 00 56 00 6f 00  O.R.A.G.E.#.V.o.
00000990: 6c 00 75 00 6d 00 65 00 23 00 7b 00 35 00 31 00  l.u.m.e.#.{.5.1.
000009a0: 38 00 36 00 34 00 39 00 61 00 62 00 2d 00 65 00  8.6.4.9.a.b.-.e.
000009b0: 62 00 39 00 39 00 2d 00 31 00 31 00 65 00 65 00  b.9.9.-.1.1.e.e.
000009c0: 2d 00 61 00 66 00 30 00 65 00 2d 00 38 00 30 00  -.a.f.0.e.-.8.0.
000009d0: 36 00 65 00 36 00 66 00 36 00 65 00 36 00 39 00  6.e.6.f.6.e.6.9.
000009e0: 36 00 33 00 7d 00 23 00 30 00 30 00 30 00 30 00  6.3.}.#.0.0.0.0.
000009f0: 30 00 30 00 37 00 36 00 42 00 46 00 32 00 30 00  0.0.7.6.B.F.2.0.
00000a00: 30 00 30 00 30 00 30 00 23 00 7b 00 35 00 33 00  0.0.0.0.#.{.5.3.
00000a10: 66 00 35 00 36 00 33 00 30 00 64 00 2d 00 62 00  f.5.6.3.0.d.-.b.
00000a20: 36 00 62 00 66 00 2d 00 31 00 31 00 64 00 30 00  6.b.f.-.1.1.d.0.
00000a30: 2d 00 39 00 34 00 66 00 32 00 2d 00 30 00 30 00  -.9.4.f.2.-.0.0.
00000a40: 61 00 30 00 63 00 39 00 31 00 65 00 66 00 62 00  a.0.c.9.1.e.f.b.
00000a50: 38 00 62 00 7d 00 00 00 5c 00 5c 00 3f 00 5c 00  8.b.}...\.\.?.\.
00000a60: 53 00 54 00 4f 00 52 00 41 00 47 00 45 00 23 00  S.T.O.R.A.G.E.#.
00000a70: 56 00 6f 00 6c 00 75 00 6d 00 65 00 53 00 6e 00  V.o.l.u.m.e.S.n.
00000a80: 61 00 70 00 73 00 68 00 6f 00 74 00 23 00 48 00  a.p.s.h.o.t.#.H.
00000a90: 61 00 72 00 64 00 64 00 69 00 73 00 6b 00 56 00  a.r.d.d.i.s.k.V.
00000aa0: 6f 00 6c 00 75 00 6d 00 65 00 53 00 6e 00 61 00  o.l.u.m.e.S.n.a.
00000ab0: 70 00 73 00 68 00 6f 00 74 00 35 00 23 00 7b 00  p.s.h.o.t.5.#.{.
00000ac0: 35 00 33 00 66 00 35 00 36 00 33 00 30 00 64 00  5.3.f.5.6.3.0.d.
00000ad0: 2d 00 62 00 36 00 62 00 66 00 2d 00 31 00 31 00  -.b.6.b.f.-.1.1.
00000ae0: 64 00 30 00 2d 00 39 00 34 00 66 00 32 00 2d 00  d.0.-.9.4.f.2.-.
00000af0: 30 00 30 00 61 00 30 00 63 00 39 00 31 00 65 00  0.0.a.0.c.9.1.e.
00000b00: 66 00 62 00 38 00 62 00 7d 00 00 00 5c 00 5c 00  f.b.8.b.}...\.\.
00000b10: 3f 00 5c 00 53 00 54 00 4f 00 52 00 41 00 47 00  ?.\.S.T.O.R.A.G.
00000b20: 45 00 23 00 56 00 6f 00 6c 00 75 00 6d 00 65 00  E.#.V.o.l.u.m.e.
00000b30: 53 00 6e 00 61 00 70 00 73 00 68 00 6f 00 74 00  S.n.a.p.s.h.o.t.
00000b40: 23 00 48 00 61 00 72 00 64 00 64 00 69 00 73 00  #.H.a.r.d.d.i.s.
00000b50: 6b 00 56 00 6f 00 6c 00 75 00 6d 00 65 00 53 00  k.V.o.l.u.m.e.S.
00000b60: 6e 00 61 00 70 00 73 00 68 00 6f 00 74 00 32 00  n.a.p.s.h.o.t.2.
00000b70: 23 00 7b 00 35 00 33 00 66 00 35 00 36 00 33 00  #.{.5.3.f.5.6.3.
00000b80: 30 00 64 00 2d 00 62 00 36 00 62 00 66 00 2d 00  0.d.-.b.6.b.f.-.
00000b90: 31 00 31 00 64 00 30 00 2d 00 39 00 34 00 66 00  1.1.d.0.-.9.4.f.
00000ba0: 32 00 2d 00 30 00 30 00 61 00 30 00 63 00 39 00  2.-.0.0.a.0.c.9.
00000bb0: 31 00 65 00 66 00 62 00 38 00 62 00 7d 00 00 00  1.e.f.b.8.b.}...
00000bc0: 00 00 00 00 00 00 00 00 50 00 00 50 d9 6c 1f 00  ........P..P.l..
00000bd0: 00 1a 91 6d 9a 02 00 00 f0 bb c5 6a 9a 02 00 00  ...m.......j....
00000be0: 00 00 00 00 00 00 00 00 00 00 af 35 e7 00 00 00  ...........5....
00000bf0: 00 00 00 00 00 00 00 00 07 00 00 00 00 00 00 00  ................
00000c00: 00 00 00 00 00 00 00 00 9a d6 fe 61 f9 7f 00 00  ...........a....
00000c10: 00 00 00 00 00 00 00 00 07 00 00 00 00 00 00 00  ................
00000c20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000c30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000c40: 07 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000c50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000c60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000c70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000c80: 00 00 00 00 00 00 00 00 79 6d 59 16 00 01 00 80  ........ymY.....
00000c90: 00 00 00 00 00 00 00 00 07 00 00 00 00 00 00 00  ................
00000ca0: 00 00 00 00 00 00 00 00 56 00 6f 00 6c 00 75 00  ........V.o.l.u.
00000cb0: 00 00 00 00 00 00 00 00 07 00 00 00 00 00 00 00  ................
00000cc0: 00 00 00 00 00 00 00 00 02 00 07 80 00 00 00 00  ................
00000cd0: 00 00 00 00 00 00 00 00 07 00 00 00 00 00 00 00  ................
00000ce0: 00 00 55 00 73 00 65 00 00 00 00 00 00 00 00 00  ..U.s.e.........
00000cf0: 36 00 66 00 36 00 65 00 00 00 00 00 00 00 00 00  6.f.6.e.........
00000d00: 07 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000d10: 30 00 30 00 31 00 31 00 00 00 00 00 00 00 00 00  0.0.1.1.........
00000d20: 00 00 00 00 00 00 00 00 98 02 21 68 9a 02 00 00  ..........!h....
00000d30: 36 00 33 00 30 00 64 00 39 00 00 39 be 69 1f 00  6.3.0.d.9..9.i..
00000d40: 40 d6 7e 6d 9a 02 00 00 90 aa 74 6d 9a 02 00 00  @.~m......tm....
00000d50: 34 00 66 00 32 00 2d 00 00 00 00 00 00 00 00 00  4.f.2.-.........
00000d60: 07 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000d70: 30 63 91 6d 9a 02 00 00 00 00 00 00 00 00 00 00  0c.m............
00000d80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000d90: 41 00 47 00 45 00 23 00 00 00 00 00 00 00 00 00  A.G.E.#.........
00000da0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000db0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000dc0: ff ff fc ff 00 00 c0 0d 00 00 12 00 00 00 00 00  ................
00000dd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000de0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000df0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000e00: fe ff fc ff 00 00 00 0e 00 00 12 00 00 00 00 00  ................
00000e10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000e20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000e30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000e40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000e50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000e60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000e70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000e80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000e90: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000ea0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000eb0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000ec0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000ed0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000ee0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000ef0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000f00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000f10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000f20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000f30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000f40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000f50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000f60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000f70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000f80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000f90: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000fa0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000fb0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000fc0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000fd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000fe0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000ff0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001000: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001010: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001020: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001030: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001040: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001050: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001080: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001090: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000010a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000010b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000010c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000010d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000010e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000010f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001100: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001110: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001120: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001130: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001140: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001150: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001160: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001170: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001180: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001190: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000011a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000011b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000011c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000011d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000011e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000011f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001200: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001210: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001220: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001230: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001240: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001250: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001260: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001270: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001280: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001290: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000012a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000012b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000012c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000012d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000012e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000012f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001300: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001310: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001320: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001330: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001340: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001350: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001360: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001370: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001380: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001390: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000013a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000013b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000013c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000013d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000013e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000013f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001400: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001410: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001420: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001430: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001440: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001450: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001460: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001470: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001480: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001490: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000014a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000014b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000014c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000014d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000014e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000014f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001500: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001510: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001520: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001530: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001540: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001550: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001560: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001570: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001580: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001590: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000015a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000015b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000015c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000015d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000015e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000015f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001600: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001610: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001620: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001630: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001640: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001650: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001660: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001670: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001680: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001690: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000016a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000016b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000016c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000016d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000016e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000016f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001700: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001710: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001720: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001730: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001740: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001750: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001760: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001770: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001780: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001790: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000017a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000017b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000017c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000017d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000017e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000017f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001800: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001810: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001820: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001830: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001840: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001850: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001860: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001870: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001880: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001890: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000018a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000018b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000018c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000018d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000018e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000018f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001900: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001910: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001920: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001930: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001940: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001950: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001960: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001970: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001980: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001990: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000019a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000019b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000019c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000019d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000019e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000019f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001a00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001a10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001a20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001a30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001a40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001a50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001a60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001a70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001a80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001a90: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001aa0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001ab0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001ac0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001ad0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001ae0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001af0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001b00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001b10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001b20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001b30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001b40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001b50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001b60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001b70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001b80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001b90: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001ba0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001bb0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001bc0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001bd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001be0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001bf0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001c00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001c10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001c20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001c30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001c40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001c50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001c60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001c70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001c80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001c90: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001ca0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001cb0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001cc0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001cd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001ce0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001cf0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001d00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001d10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001d20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001d30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001d40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001d50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001d60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001d70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001d80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001d90: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001da0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001db0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001dc0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001dd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001de0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001df0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001e00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001e10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001e20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001e30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001e40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001e50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001e60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001e70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001e80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001e90: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001ea0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001eb0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001ec0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001ed0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001ee0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001ef0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001f00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001f10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001f20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001f30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001f40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001f50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001f60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001f70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001f80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001f90: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001fa0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001fb0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001fc0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001fd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001fe0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00001ff0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002000: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002010: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002020: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002030: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002040: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002050: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002080: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002090: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000020a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000020b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000020c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000020d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000020e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000020f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002100: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002110: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002120: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002130: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002140: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002150: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002160: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002170: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002180: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002190: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000021a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000021b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000021c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000021d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000021e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000021f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002200: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002210: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002220: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002230: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002240: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002250: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002260: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002270: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002280: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002290: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000022a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000022b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000022c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000022d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000022e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000022f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002300: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002310: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002320: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002330: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002340: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002350: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002360: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002370: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002380: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002390: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000023a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000023b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000023c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000023d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000023e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000023f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002400: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002410: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002420: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002430: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002440: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002450: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002460: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002470: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002480: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002490: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000024a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000024b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000024c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000024d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000024e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000024f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002500: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002510: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002520: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002530: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002540: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002550: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002560: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002570: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002580: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002590: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000025a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000025b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000025c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000025d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000025e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000025f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002600: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002610: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002620: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002630: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002640: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002650: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002660: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002670: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002680: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002690: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000026a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000026b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000026c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000026d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000026e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000026f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002700: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002710: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002720: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002730: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002740: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002750: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002760: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002770: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002780: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002790: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000027a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000027b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000027c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000027d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000027e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000027f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002800: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002810: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002820: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002830: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002840: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002850: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002860: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002870: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002880: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002890: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000028a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000028b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000028c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000028d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000028e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000028f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002900: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002910: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002920: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002930: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002940: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002950: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002960: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002970: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002980: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002990: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000029a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000029b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000029c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000029d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000029e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000029f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002a00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002a10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002a20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002a30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002a40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002a50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002a60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002a70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002a80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002a90: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002aa0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002ab0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002ac0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002ad0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002ae0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002af0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002b00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002b10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002b20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002b30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002b40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002b50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002b60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002b70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002b80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002b90: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002ba0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002bb0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002bc0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002bd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002be0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002bf0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002c00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002c10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002c20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002c30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002c40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002c50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002c60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002c70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002c80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002c90: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002ca0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002cb0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002cc0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002cd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002ce0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002cf0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002d00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002d10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002d20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002d30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002d40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002d50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002d60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002d70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002d80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002d90: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002da0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002db0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002dc0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002dd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002de0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002df0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002e00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002e10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002e20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002e30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002e40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002e50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002e60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002e70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002e80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002e90: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002ea0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002eb0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002ec0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002ed0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002ee0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002ef0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002f00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002f10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002f20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002f30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002f40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002f50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002f60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002f70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002f80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002f90: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002fa0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002fb0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002fc0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002fd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002fe0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00002ff0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003000: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003010: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003020: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003030: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003040: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003050: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003080: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003090: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000030a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000030b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000030c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000030d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000030e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000030f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003100: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003110: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003120: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003130: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003140: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003150: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003160: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003170: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003180: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003190: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000031a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000031b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000031c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000031d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000031e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000031f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003200: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003210: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003220: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003230: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003240: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003250: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003260: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003270: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003280: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003290: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000032a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000032b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000032c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000032d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000032e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000032f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003300: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003310: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003320: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003330: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003340: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003350: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003360: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003370: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003380: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003390: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000033a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000033b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000033c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000033d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000033e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000033f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003400: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003410: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003420: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003430: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003440: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003450: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003460: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003470: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003480: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003490: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000034a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000034b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000034c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000034d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000034e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000034f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003500: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003510: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003520: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003530: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003540: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003550: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003560: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003570: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003580: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003590: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000035a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000035b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000035c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000035d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000035e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000035f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003600: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003610: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003620: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003630: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003640: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003650: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003660: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003670: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003680: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003690: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000036a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000036b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000036c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000036d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000036e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000036f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003700: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003710: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003720: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003730: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003740: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003750: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003760: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003770: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003780: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003790: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000037a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000037b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000037c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000037d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000037e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000037f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003800: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003810: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003820: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003830: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003840: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003850: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003860: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003870: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003880: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003890: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000038a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000038b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000038c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000038d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000038e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000038f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003900: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003910: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003920: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003930: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003940: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003950: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003960: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003970: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003980: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003990: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000039a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000039b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000039c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000039d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000039e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000039f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003a00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003a10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003a20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003a30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003a40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003a50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003a60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003a70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003a80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003a90: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003aa0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003ab0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003ac0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003ad0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003ae0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003af0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003b00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003b10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003b20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003b30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003b40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003b50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003b60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003b70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003b80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003b90: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003ba0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003bb0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003bc0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003bd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003be0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003bf0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003c00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003c10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003c20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003c30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003c40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003c50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003c60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003c70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003c80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003c90: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003ca0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003cb0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003cc0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003cd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003ce0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003cf0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003d00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003d10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003d20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003d30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003d40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003d50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003d60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003d70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003d80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003d90: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003da0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003db0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003dc0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003dd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003de0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003df0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003e00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003e10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003e20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003e30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003e40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003e50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003e60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003e70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003e80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003e90: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003ea0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003eb0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003ec0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003ed0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003ee0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003ef0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003f00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003f10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003f20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003f30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003f40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003f50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003f60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003f70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003f80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003f90: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003fa0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003fb0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003fc0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003fd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003fe0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00003ff0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004000: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004010: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004020: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004030: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004040: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004050: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004080: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004090: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000040a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000040b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000040c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000040d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000040e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000040f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004100: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004110: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004120: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004130: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004140: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004150: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004160: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004170: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004180: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004190: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000041a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000041b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000041c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000041d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000041e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000041f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004200: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004210: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004220: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004230: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004240: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004250: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004260: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004270: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004280: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004290: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000042a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000042b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000042c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000042d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000042e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000042f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004300: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004310: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004320: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004330: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004340: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004350: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004360: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004370: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004380: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004390: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000043a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000043b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000043c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000043d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000043e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000043f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004400: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004410: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004420: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004430: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004440: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004450: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004460: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004470: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004480: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004490: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000044a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000044b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000044c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000044d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000044e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000044f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004500: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004510: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004520: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004530: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004540: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004550: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004560: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004570: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004580: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004590: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000045a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000045b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000045c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000045d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000045e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000045f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004600: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004610: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004620: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004630: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004640: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004650: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004660: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004670: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004680: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004690: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000046a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000046b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000046c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000046d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000046e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000046f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004700: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004710: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004720: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004730: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004740: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004750: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004760: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004770: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004780: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004790: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000047a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000047b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000047c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000047d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000047e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000047f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004800: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004810: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004820: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004830: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004840: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004850: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004860: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004870: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004880: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004890: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000048a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000048b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000048c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000048d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000048e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000048f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004900: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004910: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004920: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004930: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004940: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004950: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004960: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004970: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004980: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004990: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000049a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000049b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000049c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000049d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000049e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000049f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004a00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004a10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004a20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004a30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004a40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004a50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004a60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004a70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004a80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004a90: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004aa0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004ab0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004ac0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004ad0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004ae0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004af0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004b00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004b10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004b20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004b30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004b40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004b50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004b60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004b70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004b80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004b90: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004ba0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004bb0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004bc0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004bd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004be0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004bf0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004c00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004c10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004c20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004c30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004c40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004c50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004c60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004c70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004c80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004c90: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004ca0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004cb0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004cc0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004cd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004ce0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004cf0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004d00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004d10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004d20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004d30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004d40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004d50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004d60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004d70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004d80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004d90: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004da0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004db0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004dc0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004dd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004de0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004df0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004e00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004e10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004e20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004e30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004e40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004e50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004e60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004e70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004e80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004e90: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004ea0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004eb0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004ec0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004ed0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004ee0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004ef0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004f00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004f10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004f20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004f30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004f40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004f50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004f60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004f70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004f80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004f90: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004fa0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004fb0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004fc0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004fd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004fe0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00004ff0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005000: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005010: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005020: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005030: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005040: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005050: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005080: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005090: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000050a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000050b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000050c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000050d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000050e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000050f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005100: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005110: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005120: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005130: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005140: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005150: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005160: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005170: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005180: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005190: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000051a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000051b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000051c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000051d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000051e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000051f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005200: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005210: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005220: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005230: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005240: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005250: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005260: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005270: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005280: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005290: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000052a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000052b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000052c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000052d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000052e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000052f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005300: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005310: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005320: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005330: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005340: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005350: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005360: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005370: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005380: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005390: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000053a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000053b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000053c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000053d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000053e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000053f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005400: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005410: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005420: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005430: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005440: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005450: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005460: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005470: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005480: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005490: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000054a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000054b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000054c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000054d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000054e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000054f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005500: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005510: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005520: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005530: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005540: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005550: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005560: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005570: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005580: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005590: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000055a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000055b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000055c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000055d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000055e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000055f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005600: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005610: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005620: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005630: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005640: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005650: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005660: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005670: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005680: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005690: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000056a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000056b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000056c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000056d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000056e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000056f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005700: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005710: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005720: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005730: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005740: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005750: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005760: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005770: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005780: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005790: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000057a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000057b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000057c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000057d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000057e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000057f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005800: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005810: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005820: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005830: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005840: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005850: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005860: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005870: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005880: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005890: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000058a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000058b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000058c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000058d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000058e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000058f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005900: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005910: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005920: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005930: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005940: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005950: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005960: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005970: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005980: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005990: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000059a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000059b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000059c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000059d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000059e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000059f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005a00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005a10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005a20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005a30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005a40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005a50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005a60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005a70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005a80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005a90: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005aa0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005ab0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005ac0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005ad0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005ae0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005af0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005b00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005b10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005b20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005b30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005b40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005b50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005b60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005b70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005b80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005b90: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005ba0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005bb0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005bc0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005bd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005be0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005bf0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005c00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005c10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005c20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005c30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005c40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005c50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005c60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005c70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005c80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005c90: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005ca0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005cb0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005cc0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005cd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005ce0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005cf0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005d00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005d10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005d20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005d30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005d40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005d50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005d60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005d70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005d80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005d90: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005da0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005db0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005dc0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005dd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005de0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005df0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005e00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005e10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005e20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005e30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005e40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005e50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005e60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005e70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005e80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005e90: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005ea0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005eb0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005ec0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005ed0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005ee0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005ef0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005f00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005f10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005f20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005f30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005f40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005f50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005f60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005f70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005f80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005f90: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005fa0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005fb0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005fc0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005fd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005fe0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00005ff0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006000: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006010: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006020: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006030: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006040: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006050: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006080: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006090: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000060a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000060b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000060c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000060d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000060e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000060f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006100: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006110: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006120: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006130: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006140: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006150: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006160: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006170: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006180: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006190: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000061a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000061b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000061c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000061d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000061e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000061f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006200: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006210: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006220: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006230: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006240: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006250: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006260: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006270: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006280: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006290: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000062a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000062b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000062c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000062d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000062e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000062f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006300: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006310: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006320: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006330: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006340: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006350: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006360: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006370: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006380: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006390: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000063a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000063b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000063c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000063d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000063e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000063f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006400: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006410: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006420: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006430: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006440: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006450: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006460: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006470: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006480: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006490: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000064a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000064b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000064c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000064d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000064e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000064f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006500: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006510: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006520: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006530: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006540: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006550: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006560: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006570: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006580: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006590: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000065a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000065b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000065c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000065d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000065e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000065f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006600: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006610: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006620: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006630: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006640: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006650: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006660: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006670: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006680: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006690: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000066a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000066b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000066c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000066d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000066e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000066f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006700: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006710: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006720: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006730: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006740: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006750: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006760: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006770: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006780: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006790: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000067a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000067b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000067c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000067d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000067e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000067f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006800: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006810: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006820: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006830: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006840: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006850: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006860: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006870: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006880: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006890: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000068a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000068b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000068c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000068d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000068e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000068f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006900: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006910: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006920: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006930: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006940: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006950: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006960: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006970: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006980: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006990: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000069a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000069b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000069c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000069d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000069e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000069f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006a00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006a10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006a20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006a30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006a40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006a50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006a60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006a70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006a80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006a90: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006aa0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006ab0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006ac0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006ad0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006ae0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006af0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006b00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006b10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006b20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006b30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006b40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006b50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006b60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006b70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006b80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006b90: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006ba0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006bb0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006bc0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006bd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006be0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006bf0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006c00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006c10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006c20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006c30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006c40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006c50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006c60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006c70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006c80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006c90: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006ca0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006cb0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006cc0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006cd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006ce0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006cf0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006d00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006d10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006d20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006d30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006d40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006d50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006d60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006d70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006d80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006d90: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006da0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006db0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006dc0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006dd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006de0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006df0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006e00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006e10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006e20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006e30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006e40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006e50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006e60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006e70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006e80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006e90: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006ea0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006eb0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006ec0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006ed0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006ee0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006ef0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006f00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006f10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006f20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006f30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006f40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006f50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006f60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006f70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006f80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006f90: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006fa0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006fb0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006fc0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006fd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006fe0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00006ff0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007000: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007010: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007020: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007030: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007040: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007050: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007080: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007090: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000070a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000070b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000070c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000070d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000070e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000070f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007100: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007110: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007120: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007130: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007140: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007150: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007160: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007170: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007180: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007190: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000071a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000071b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000071c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000071d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000071e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000071f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007200: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007210: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007220: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007230: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007240: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007250: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007260: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007270: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007280: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007290: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000072a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000072b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000072c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000072d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000072e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000072f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007300: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007310: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007320: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007330: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007340: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007350: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007360: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007370: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007380: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007390: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000073a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000073b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000073c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000073d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000073e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000073f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007400: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007410: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007420: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007430: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007440: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007450: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007460: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007470: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007480: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007490: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000074a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000074b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000074c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000074d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000074e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000074f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007500: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007510: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007520: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007530: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007540: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007550: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007560: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007570: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007580: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00007590: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000075a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000075b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000075c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000075d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000075e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000075f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................

```

it doesn't really seem interesting for our purposes.

Here is then the thing:

```


int FUN_140065ad8(LPCSTR filename,uint some_integer)

{
  int *piVar1;
  int iVar2;
  uint uVar3;
  HWND pHVar4;
  ulonglong uVar5;
  HGLOBAL hMem;
  LPVOID pvVar6;
  int iVar7;
  int iVar8;
  HWND window_thing_object [2];

  iVar2 = 0;
  SetCursor(DAT_1400baa28);
  iVar8 = 1;
  some_thing_global = 1;
  pHVar4 = FUN_1400657f0(filename);
  if (pHVar4 == (HWND)0x0) {
    if (some_integer == 0x5d) {
      some_integer = 0xfffffffd;
      iVar7 = iVar8;
    }
    else {
      iVar7 = 0;
      if (some_integer == 0x5c) {
        some_integer = 0xfffffffe;
        iVar7 = iVar8;
      }
    }
    iVar2 = openfileastempandopenwindows(filename,some_integer,window_thing_object);
    if (window_thing_object[0] == (HWND)0x0) {
      iVar2 = iVar8;
    }
    if (iVar2 != 0) goto LAB_140065c1c;
    if (((some_integer == 0xfffffffe) || (some_integer == 2)) || (some_integer - 0x5b < 2)) {
      uVar5 = checkvaliddatathing(window_thing_object[0],filename,some_integer);
      iVar2 = (int)uVar5;
      if (iVar2 != 0) goto LAB_140065c1c;
    }
    if (((iVar7 != 0) && (window_thing_object[0] != (HWND)0x0)) &&
       (hMem = (HGLOBAL)GetWindowLongPtrA(window_thing_object[0],8), hMem != (HGLOBAL)0x0)) {
      pvVar6 = GlobalLock(hMem);
      piVar1 = *(int **)((longlong)pvVar6 + 0x2ca);
      if (((piVar1 != (int *)0x0) && (*piVar1 != 0)) && (*(longlong *)(piVar1 + 3) != 0)) {
        *(undefined4 *)(*(longlong *)(piVar1 + 3) + 0x60) = 2;
      }
      GlobalUnlock(hMem);
    }
  }
  else {
    BringWindowToTop(pHVar4);
  }
  if (DAT_1400991b0 != (HWND)0x0) {
    uVar3 = FUN_140065a10(DAT_1400991b0);
    if (uVar3 == 0) {
      pHVar4 = GetParent(DAT_1400991b0);
      SendMessageA(pHVar4,0x10,0,0);
    }
    DAT_1400991b0 = (HWND)0x0;
  }
LAB_140065c1c:
  SetCursor(DAT_1400baa20);
  some_thing_global = 0;
  return iVar2;
}




Säikeen tunnist Osoite           Paluun kohde     Paluun lähde     Kok Muistialue   Kommentti
27468 - Pääsäie
                000000E7356FEE28 00007FF69A68E5E9 00007FF69A68E9FE 90  Käyttäjäalue orgchart.00007FF69A68E9FE
                000000E7356FEEB8 00007FF69A6A592E 00007FF69A68E5E9 40  Käyttäjäalue orgchart.00007FF69A68E5E9
                000000E7356FEEF8 00007FF69A6A5B81 00007FF69A6A592E 40  Käyttäjäalue orgchart.00007FF69A6A592E
                000000E7356FEF38 00007FF69A6A5C9F 00007FF69A6A5B81 150 Käyttäjäalue orgchart.00007FF69A6A5B81
                000000E7356FF088 00007FF69A6976DF 00007FF69A6A5C9F 50  Käyttäjäalue orgchart.00007FF69A6A5C9F
                000000E7356FF0D8 00007FF69A697F98 00007FF69A6976DF 9E0 Käyttäjäalue orgchart.00007FF69A6976DF
                000000E7356FFAB8 00007FF960C183F1 00007FF69A697F98 160 Järjestelmä  orgchart.00007FF69A697F98
                000000E7356FFC18 00007FF960C17EB1 00007FF960C183F1 80  Järjestelmä  user32.DispatchMessageW+741
                000000E7356FFC98 00007FF69A698D81 00007FF960C17EB1 1D0 Käyttäjäalue user32.DispatchMessageW+201
                000000E7356FFE68 00007FF69A6CD472 00007FF69A698D81 40  Käyttäjäalue orgchart.00007FF69A698D81
                000000E7356FFEA8 00007FF960B3259D 00007FF69A6CD472 30  Järjestelmä  orgchart.00007FF69A6CD472
                000000E7356FFED8 00007FF96200AF38 00007FF960B3259D 80  Järjestelmä  kernel32.BaseThreadInitThunk+1D
                000000E7356FFF58 0000000000000000 00007FF96200AF38     Käyttäjäalue ntdll.RtlUserThreadStart+28
15288
                000000E7357FF8D8 00007FF961FE586E 00007FF962053FF4 2E0 Järjestelmä  ntdll.NtWaitForWorkViaWorkerFactory+14
                000000E7357FFBB8 00007FF960B3259D 00007FF961FE586E 30  Järjestelmä  ntdll.RtlClearThreadWorkOnBehalfTicket+35E
                000000E7357FFBE8 00007FF96200AF38 00007FF960B3259D 80  Järjestelmä  kernel32.BaseThreadInitThunk+1D
                000000E7357FFC68 0000000000000000 00007FF96200AF38     Käyttäjäalue ntdll.RtlUserThreadStart+28
23936
                000000E7358FF9F8 00007FF961FE586E 00007FF962053FF4 2E0 Järjestelmä  ntdll.NtWaitForWorkViaWorkerFactory+14
                000000E7358FFCD8 00007FF960B3259D 00007FF961FE586E 30  Järjestelmä  ntdll.RtlClearThreadWorkOnBehalfTicket+35E
                000000E7358FFD08 00007FF96200AF38 00007FF960B3259D 80  Järjestelmä  kernel32.BaseThreadInitThunk+1D
                000000E7358FFD88 0000000000000000 00007FF96200AF38     Käyttäjäalue ntdll.RtlUserThreadStart+28
11604
                000000E735CFF498 00007FF961FE586E 00007FF962053FF4 2E0 Järjestelmä  ntdll.NtWaitForWorkViaWorkerFactory+14
                000000E735CFF778 00007FF960B3259D 00007FF961FE586E 30  Järjestelmä  ntdll.RtlClearThreadWorkOnBehalfTicket+35E
                000000E735CFF7A8 00007FF96200AF38 00007FF960B3259D 80  Järjestelmä  kernel32.BaseThreadInitThunk+1D
                000000E735CFF828 0000000000000000 00007FF96200AF38     Käyttäjäalue ntdll.RtlUserThreadStart+28
14596
                000000E7359FF868 00007FF961FE586E 00007FF962053FF4 2E0 Järjestelmä  ntdll.NtWaitForWorkViaWorkerFactory+14
                000000E7359FFB48 00007FF960B3259D 00007FF961FE586E 30  Järjestelmä  ntdll.RtlClearThreadWorkOnBehalfTicket+35E
                000000E7359FFB78 00007FF96200AF38 00007FF960B3259D 80  Järjestelmä  kernel32.BaseThreadInitThunk+1D
                000000E7359FFBF8 0000000000000000 00007FF96200AF38     Käyttäjäalue ntdll.RtlUserThreadStart+28
33260
                000000E735BFFA88 00007FF961FE586E 00007FF962053FF4 2E0 Järjestelmä  ntdll.NtWaitForWorkViaWorkerFactory+14
                000000E735BFFD68 00007FF960B3259D 00007FF961FE586E 30  Järjestelmä  ntdll.RtlClearThreadWorkOnBehalfTicket+35E
                000000E735BFFD98 00007FF96200AF38 00007FF960B3259D 80  Järjestelmä  kernel32.BaseThreadInitThunk+1D
                000000E735BFFE18 0000000000000000 00007FF96200AF38     Käyttäjäalue ntdll.RtlUserThreadStart+28
31036
                000000E735EFFAE8 00007FF961FE586E 00007FF962053FF4 2E0 Järjestelmä  ntdll.NtWaitForWorkViaWorkerFactory+14
                000000E735EFFDC8 00007FF960B3259D 00007FF961FE586E 30  Järjestelmä  ntdll.RtlClearThreadWorkOnBehalfTicket+35E
                000000E735EFFDF8 00007FF96200AF38 00007FF960B3259D 80  Järjestelmä  kernel32.BaseThreadInitThunk+1D
                000000E735EFFE78 0000000000000000 00007FF96200AF38     Käyttäjäalue ntdll.RtlUserThreadStart+28
24776
                000000E735FFF808 00007FF961FE586E 00007FF962053FF4 2E0 Järjestelmä  ntdll.NtWaitForWorkViaWorkerFactory+14
                000000E735FFFAE8 00007FF960B3259D 00007FF961FE586E 30  Järjestelmä  ntdll.RtlClearThreadWorkOnBehalfTicket+35E
                000000E735FFFB18 00007FF96200AF38 00007FF960B3259D 80  Järjestelmä  kernel32.BaseThreadInitThunk+1D
                000000E735FFFB98 0000000000000000 00007FF96200AF38     Käyttäjäalue ntdll.RtlUserThreadStart+28
38992
                000000E7360FF9E8 00007FF961FE586E 00007FF962053FF4 2E0 Järjestelmä  ntdll.NtWaitForWorkViaWorkerFactory+14
                000000E7360FFCC8 00007FF960B3259D 00007FF961FE586E 30  Järjestelmä  ntdll.RtlClearThreadWorkOnBehalfTicket+35E
                000000E7360FFCF8 00007FF96200AF38 00007FF960B3259D 80  Järjestelmä  kernel32.BaseThreadInitThunk+1D
                000000E7360FFD78 0000000000000000 00007FF96200AF38     Käyttäjäalue ntdll.RtlUserThreadStart+28
34192
                000000E7361FF468 00007FF961FE586E 00007FF962053FF4 2E0 Järjestelmä  ntdll.NtWaitForWorkViaWorkerFactory+14
                000000E7361FF748 00007FF960B3259D 00007FF961FE586E 30  Järjestelmä  ntdll.RtlClearThreadWorkOnBehalfTicket+35E
                000000E7361FF778 00007FF96200AF38 00007FF960B3259D 80  Järjestelmä  kernel32.BaseThreadInitThunk+1D
                000000E7361FF7F8 0000000000000000 00007FF96200AF38     Käyttäjäalue ntdll.RtlUserThreadStart+28
34832
                000000E7362FFC48 00007FF961FE586E 00007FF962053FF4 2E0 Järjestelmä  ntdll.NtWaitForWorkViaWorkerFactory+14
                000000E7362FFF28 00007FF960B3259D 00007FF961FE586E 30  Järjestelmä  ntdll.RtlClearThreadWorkOnBehalfTicket+35E
                000000E7362FFF58 00007FF96200AF38 00007FF960B3259D 80  Järjestelmä  kernel32.BaseThreadInitThunk+1D
                000000E7362FFFD8 0000000000000000 00007FF96200AF38     Käyttäjäalue ntdll.RtlUserThreadStart+28
41520
                000000E7363FF7A8 00007FF961FE586E 00007FF962053FF4 2E0 Järjestelmä  ntdll.NtWaitForWorkViaWorkerFactory+14
                000000E7363FFA88 00007FF960B3259D 00007FF961FE586E 30  Järjestelmä  ntdll.RtlClearThreadWorkOnBehalfTicket+35E
                000000E7363FFAB8 00007FF96200AF38 00007FF960B3259D 80  Järjestelmä  kernel32.BaseThreadInitThunk+1D
                000000E7363FFB38 0000000000000000 00007FF96200AF38     Käyttäjäalue ntdll.RtlUserThreadStart+28
43140
                000000E735DFF8F8 00007FF961FE586E 00007FF962053FF4 2E0 Järjestelmä  ntdll.NtWaitForWorkViaWorkerFactory+14
                000000E735DFFBD8 00007FF960B3259D 00007FF961FE586E 30  Järjestelmä  ntdll.RtlClearThreadWorkOnBehalfTicket+35E
                000000E735DFFC08 00007FF96200AF38 00007FF960B3259D 80  Järjestelmä  kernel32.BaseThreadInitThunk+1D
                000000E735DFFC88 0000000000000000 00007FF96200AF38     Käyttäjäalue ntdll.RtlUserThreadStart+28
15772
                000000E735AFF4A8 00007FF961FE586E 00007FF962053FF4 2E0 Järjestelmä  ntdll.NtWaitForWorkViaWorkerFactory+14
                000000E735AFF788 00007FF960B3259D 00007FF961FE586E 30  Järjestelmä  ntdll.RtlClearThreadWorkOnBehalfTicket+35E
                000000E735AFF7B8 00007FF96200AF38 00007FF960B3259D 80  Järjestelmä  kernel32.BaseThreadInitThunk+1D
                000000E735AFF838 0000000000000000 00007FF96200AF38     Käyttäjäalue ntdll.RtlUserThreadStart+28
4304
                000000E7365FF548 00007FF961FE586E 00007FF962053FF4 2E0 Järjestelmä  ntdll.NtWaitForWorkViaWorkerFactory+14
                000000E7365FF828 00007FF960B3259D 00007FF961FE586E 30  Järjestelmä  ntdll.RtlClearThreadWorkOnBehalfTicket+35E
                000000E7365FF858 00007FF96200AF38 00007FF960B3259D 80  Järjestelmä  kernel32.BaseThreadInitThunk+1D
                000000E7365FF8D8 0000000000000000 00007FF96200AF38     Käyttäjäalue ntdll.RtlUserThreadStart+28
8836
                000000E7364FF408 00007FF95F556849 00007FF962050EF4 2E0 Järjestelmä  ntdll.NtWaitForMultipleObjects+14
                000000E7364FF6E8 00007FF9607E07AD 00007FF95F556849 2A0 Järjestelmä  kernelbase.WaitForMultipleObjectsEx+E9
                000000E7364FF988 00007FF9607E061A 00007FF9607E07AD 50  Järjestelmä  combase.CoFreeUnusedLibrariesEx+82D
                000000E7364FF9D8 00007FF9607E040F 00007FF9607E061A 80  Järjestelmä  combase.CoFreeUnusedLibrariesEx+69A
                000000E7364FFA58 00007FF9607E0829 00007FF9607E040F 30  Järjestelmä  combase.CoFreeUnusedLibrariesEx+48F
                000000E7364FFA88 00007FF960B3259D 00007FF9607E0829 30  Järjestelmä  combase.CoFreeUnusedLibrariesEx+8A9
                000000E7364FFAB8 00007FF96200AF38 00007FF960B3259D 80  Järjestelmä  kernel32.BaseThreadInitThunk+1D
                000000E7364FFB38 0000000000000000 00007FF96200AF38     Käyttäjäalue ntdll.RtlUserThreadStart+28



0x6519f


```

Here is the bullshit thing:

```

void FUN_140065f0c(int param_1)

{
  int iVar1;
  uint some_integer;
  LPVOID pvVar2;
  HWND pHVar3;
  char *pcVar4;
  int iVar5;
  longlong lVar6;
  char *pcVar7;
  undefined auStack_158 [32];
  HGLOBAL local_138 [2];
  char maybeinputfilename [272];
  ulonglong local_18;

  local_18 = DAT_140098000 ^ (ulonglong)auStack_158;
  if (0x70 < param_1) {
    maybeinputfilename[0] = '\0';
    iVar1 = FUN_140047020(DAT_1400982d0,100,0x70,local_138);
    if (iVar1 == 0) {
      pvVar2 = GlobalLock(local_138[0]);
      iVar1 = 0x75;
      iVar5 = *(int *)((longlong)pvVar2 + 0x10) + param_1;
      if (iVar5 + -0x71 < 4) {
        iVar1 = 0x71;
      }
      lVar6 = 0x106;
      pcVar7 = (char *)((longlong)pvVar2 + (longlong)(iVar5 - iVar1) * 0x106 + 0x11a);
      pcVar4 = maybeinputfilename;
      do {
        if ((lVar6 == -0x7ffffef8) || (*pcVar7 == '\0')) break;
        *pcVar4 = *pcVar7;
        pcVar7 = pcVar7 + 1;
        pcVar4 = pcVar4 + 1;
        lVar6 = lVar6 + -1;
      } while (lVar6 != 0);
      pcVar7 = pcVar4 + -1;
      if (lVar6 != 0) {
        pcVar7 = pcVar4;
      }
      *pcVar7 = '\0';
      GlobalUnlock(local_138[0]);
    }
    iVar1 = lstrlenA(maybeinputfilename);
    if (iVar1 != 0) {
      some_integer = 3;
      pHVar3 = FUN_1400657f0(maybeinputfilename);
      if (pHVar3 == (HWND)0x0) {
        some_integer = FUN_14006864c(maybeinputfilename);
        if (some_integer == 0) goto LAB_140066016;
      }
      load_file(maybeinputfilename,some_integer);
    }
  }
LAB_140066016:
  FUN_14008d510(local_18 ^ (ulonglong)auStack_158);
  return;
}


```

Let's clean it up a bit more...

Here is a cleaned up version:

```

void FUN_140065f0c(int param_1)

{
  uint some_integer;
  LPVOID pvVar1;
  int isfilenamenull;
  HWND pHVar2;
  char *str1;
  int iVar3;
  longlong counter;
  char *str2;
  undefined auStack_158 [32];
  HGLOBAL local_138 [2];
  char maybeinputfilename [272];
  ulonglong local_18;

  local_18 = DAT_140098000 ^ (ulonglong)auStack_158;
  if (0x70 < param_1) {
    maybeinputfilename[0] = '\0';
    isfilenamenull = FUN_140047020(DAT_1400982d0,100,0x70,local_138);
    if (isfilenamenull == 0) {
      pvVar1 = GlobalLock(local_138[0]);
      isfilenamenull = 0x75;
      iVar3 = *(int *)((longlong)pvVar1 + 0x10) + param_1;
      if (iVar3 + -0x71 < 4) {
        isfilenamenull = 0x71;
      }
      counter = 0x106;
      str2 = (char *)((longlong)pvVar1 + (longlong)(iVar3 - isfilenamenull) * 0x106 + 0x11a);
      str1 = maybeinputfilename;
      do {
        if ((counter == -0x7ffffef8) || (*str2 == '\0')) break;
        *str1 = *str2;
        str2 = str2 + 1;
        str1 = str1 + 1;
        counter = counter + -1;
      } while (counter != 0);
      str2 = str1 + -1;
      if (counter != 0) {
        str2 = str1;
      }
      *str2 = '\0';
      GlobalUnlock(local_138[0]);
    }
    isfilenamenull = lstrlenA(maybeinputfilename);
    if (isfilenamenull != 0) {
      some_integer = 3;
      pHVar2 = FUN_1400657f0(maybeinputfilename);
      if (pHVar2 == (HWND)0x0) {
        some_integer = FUN_14006864c(maybeinputfilename);
        if (some_integer == 0) goto LAB_140066016;
      }
      load_file(maybeinputfilename,some_integer);
    }
  }
LAB_140066016:
  FUN_14008d510(local_18 ^ (ulonglong)auStack_158);
  return;
}



```

So the file loading function is actually just here: load_file(maybeinputfilename,some_integer);

Idk, here is actually the thing:

```

void FUN_140065c48(LPCSTR filename)

{
  int iVar1;
  undefined8 uVar2;
  undefined auStack_148 [32];
  CHAR local_128 [272];
  ulonglong local_18;

  local_18 = DAT_140098000 ^ (ulonglong)auStack_148;
  uVar2 = FUN_14006315c();
  if ((int)uVar2 == 0) {
    if ((filename == (LPCSTR)0x0) || (*filename == (char)uVar2)) {
      local_128[0] = '\0';
      iVar1 = FUN_1400689b4(local_128);
      if (iVar1 == 0) goto LAB_140065c9f;
      filename = local_128;
    }
    load_file(filename,2);
  }
LAB_140065c9f:
  FUN_14008d510(local_18 ^ (ulonglong)auStack_148);
  return;
}

```

Here is the actual load function:

```


ulonglong checkvaliddatathing(HWND window_handle,LPCSTR filename,int some_integer)

{
  int iVar1;
  BOOL BVar2;
  ulonglong uVar3;
  HWND pHVar4;
  HGLOBAL hMem;
  int *piVar5;
  uint uVar6;

  if ((some_integer - 0x5aU < 2) || (some_integer == -0x5b)) {
    uVar6 = 1;
  }
  else {
    uVar6 = 0;
  }
  iVar1 = -some_integer;
  if (-1 < some_integer) {
    iVar1 = some_integer;
  }
  uVar3 = check_buffer_check(window_handle,filename,(uint)(some_integer == 0x5b),
                             (uint)((iVar1 - 0x5aU & 0xfffffffd) != 0),(uint)(some_integer != -0x 5b)
                             ,uVar6);
  if ((int)uVar3 == 0) {
    pHVar4 = GetParent(window_handle);
    BVar2 = IsWindowVisible(pHVar4);
    if ((BVar2 == 0) && (some_integer != 0x5c)) {
      pHVar4 = GetParent(window_handle);
      ShowWindow(pHVar4,5);
      pHVar4 = GetParent(window_handle);
      SendMessageA(pHVar4,6,1,1);
      pHVar4 = GetParent(window_handle);
      FUN_14005a84c(pHVar4);
    }
    pHVar4 = GetParent(window_handle);
    hMem = (HGLOBAL)GetWindowLongPtrA(pHVar4,0);
    piVar5 = (int *)GlobalLock(hMem);
    if (*piVar5 == 0) {
      FUN_140066038((char *)(piVar5 + 1));
    }
    GlobalUnlock(hMem);
  }
  else {
    pHVar4 = GetParent(window_handle);
    if (some_integer != 0x5c) {
      FUN_140067690(pHVar4);
      DefMDIChildProcA(pHVar4,0x10,0,0);
    }
  }
  return uVar3 & 0xffffffff;
}


```

The check_buffer_check function is actually the buffer load function, so let's rename it to buffer_load


Here are just the offset shit in python just in case:

```

oof@elskun-lppri:/mnt/c/Users/elsku/orgpwn$ python3
Python 3.12.3 (main, Nov  6 2024, 18:32:19) [GCC 13.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> hex(0x00007FF69A6878EB-0x00007FF69A640000)
'0x478eb'
>>> hex(0x00007FF69A687AA0-0x00007FF69A640000)
'0x47aa0'
>>> hex(0x00007FF69A6A4AF6-0x00007FF69A640000)
'0x64af6'
>>>

```

So therefore here:

```


ulonglong buffer_load(HWND window_handle,LPCSTR original_filename,int param_3,int param_4,
                     int param_5,uint param_6)

{
  undefined8 *puVar1;
  uint extraout_EAX;
  uint *window_lock;
  ulonglong uVar2;
  undefined8 uVar3;
  LPVOID pvVar4;
  HWND pHVar5;
  HGLOBAL hMem;
  int *piVar6;
  undefined4 *puVar7;
  undefined *puVar8;
  uint *puVar9;
  uint return_value;
  uint uVar10;
  int iVar11;
  UINT UVar12;
  int iVar13;
  uint *opened_file;
  longlong lVar14;
  int iVar15;
  int local_58;
  uint local_54;
  HGLOBAL local_50;
  HGLOBAL local_48;

  opened_file = (uint *)0xffffffffffffffff;
  local_54 = 0;
  DAT_140099090 = (HGLOBAL)0x0;
  iVar13 = 1;
  DAT_14009908c = 0;
  local_58 = 1;
  DAT_1400980b4 = 1;
  DAT_140099088 = 0;
  DAT_140099078 = (HGLOBAL)0x0;
  DAT_140099070 = 0;
  DAT_14009906c = 0;
  DAT_1400990a0 = 0;
  if ((param_6 == 0) || (DAT_140099068 = iVar13, (DAT_1400babf6 & 0x400) == 0)) {
    DAT_140099068 = 0;
  }
  SetCursor(DAT_1400baa28);
  puVar8 = &DAT_00000008;
  some_thing_global = 1;
  local_48 = (HGLOBAL)GetWindowLongPtrA(window_handle,8);
  if (local_48 == (HGLOBAL)0x0) {
    return 1;
  }
  window_lock = (uint *)GlobalLock(local_48);
  *(undefined4 *)((longlong)window_lock + 0x56) = 5000;
  *(undefined4 *)((longlong)window_lock + 0x5a) = 5000;
  *(undefined4 *)((longlong)window_lock + 0x9a) = 10;
  *(undefined4 *)((longlong)window_lock + 0x9e) = 10;
  uVar2 = FUN_140042714((longlong)window_lock,puVar8,*(int *)((longlong)window_lock + 0xf6));
  return_value = (uint)uVar2;
  iVar11 = iVar13;
  if (return_value == 0) {
    puVar7 = &DAT_1400bb404;
    do {
      puVar7[-1] = (int)uVar2;
      return_value = (int)uVar2 + 1;
      uVar2 = (ulonglong)return_value;
      *puVar7 = 5;
      puVar7 = puVar7 + 2;
    } while ((int)return_value < 0x1e);
    puVar1 = (undefined8 *)((longlong)window_lock + 0x1da);
    uVar3 = FUN_1400470e4(*(uint *)((longlong)window_lock + 0x26),100,0x68,puVar1);
    return_value = (uint)uVar3;
    if (return_value == 0) {
      pvVar4 = GlobalLock((HGLOBAL)*puVar1);
      *(undefined8 *)((longlong)pvVar4 + 0x10) = 0;
      *(undefined8 *)((longlong)pvVar4 + 0x20) = 0;
      *(undefined4 *)((longlong)pvVar4 + 0x28) = 0;
      *(undefined8 *)((longlong)pvVar4 + 0x34) = 0;
      FUN_140048a3c((HGLOBAL)*puVar1);
      GlobalUnlock((HGLOBAL)*puVar1);
      uVar2 = FUN_140049608(*(uint *)((longlong)window_lock + 0x26),0x67);
      return_value = (uint)uVar2;
      if (return_value == 0) {
        uVar2 = FUN_140049608(*(uint *)((longlong)window_lock + 0x26),0x68);
        return_value = (uint)uVar2;
        if (return_value == 0) {
          uVar2 = FUN_140049608(*(uint *)((longlong)window_lock + 0x26),0x65);
          if ((int)uVar2 != 0) {
            return uVar2;
          }
          uVar2 = FUN_140049608(*(uint *)((longlong)window_lock + 0x26),0x66);
          if ((int)uVar2 != 0) {
            return uVar2;
          }
          DAT_140099078 = GlobalAlloc(0x42,29000);
          return_value = ~-(uint)(DAT_140099078 != (HGLOBAL)0x0) & 0x2714;
          if (DAT_140099078 != (HGLOBAL)0x0) {
            DAT_140099080 = GlobalLock(DAT_140099078);
            pHVar5 = GetParent(window_handle);
            hMem = (HGLOBAL)GetWindowLongPtrA(pHVar5,0);
            iVar15 = iVar13;
            if (hMem != (HGLOBAL)0x0) {
              piVar6 = (int *)GlobalLock(hMem);
              if ((*piVar6 == 0) &&
                 (puVar9 = *(uint **)(piVar6 + 0x84), puVar9 != (uint *)0xffffffffffffffff)) {
                SetFilePointer(puVar9,0,(PLONG)0x0,0);
                local_58 = 0;
                opened_file = puVar9;
                iVar15 = 0;
              }
              GlobalUnlock(hMem);
            }
            iVar11 = local_58;
            if ((iVar15 == 0) ||
               (opened_file = (uint *)create_file_bullshit(original_filename,0),
               opened_file != (uint *)0xffffffffffffffff)) {
              return_value = filehandle_crc_check(opened_file);
              iVar15 = iVar13;
              if (return_value == 0) {
                do {
                  puVar9 = &local_54;
                  return_value = FUN_14005333c(opened_file,puVar9,&param_6);
                  if (return_value != 0) goto LAB_14004e55f;
                  if (local_54 == 0x4003) {
                    if (iVar13 != 0) {
                      return_value = 0x5dd;
                      goto LAB_14004e55f;
                    }
                    if (iVar15 != 0) {
                      puVar9 = window_lock;
                      return_value = FUN_14004ee84(window_handle,(longlong)window_lock,opened_fil e);
                    }
                    iVar15 = 0;
LAB_14004e655:
                    if (return_value != 0) goto LAB_14004e55f;
                  }
                  else if (local_54 == 0x4005) {
                    puVar9 = opened_file;
                    return_value = FUN_14004eb64((longlong)window_lock,opened_file);
                    iVar13 = 0;
                    goto LAB_14004e655;
                  }
                } while (local_54 != 0x6001);
                if (hMem != (HGLOBAL)0x0) {
                  pvVar4 = GlobalLock(hMem);
                  *(uint *)((longlong)pvVar4 + 0x228) = (uint)(DAT_1400980b4 == 0);
                  GlobalUnlock(hMem);
                }
                if (param_3 != 0) {
                  uVar2 = FUN_140061b80((longlong)window_lock,puVar9,1);
                  return_value = (uint)uVar2;
                  if (return_value != 0) goto LAB_14004e55f;
                  uVar2 = FUN_140049480(*(uint *)((longlong)window_lock + 0x26),0x66,(int *)&para m_6
                                       );
                  return_value = (uint)uVar2;
                  if (return_value != 0) goto LAB_14004e55f;
                  iVar13 = 0;
                  if (0 < (int)param_6) {
                    do {
                      uVar2 = FUN_14004952c(*(uint *)((longlong)window_lock + 0x26),0x66,iVar13,
                                            (int *)&local_54);
                      return_value = (uint)uVar2;
                      if ((return_value != 0) ||
                         (return_value = FUN_140047020(*(uint *)((longlong)window_lock + 0x26),0x 66,
                                                       local_54,&local_50), return_value != 0))
                      goto LAB_14004e55f;
                      uVar10 = 0;
                      do {
                        piVar6 = (int *)FUN_14007ac74(local_50,uVar10);
                        if ((((piVar6 != (int *)0x0) && (*piVar6 == 1)) &&
                            (lVar14 = (longlong)piVar6[2],
                            -1 < *(int *)(lVar14 + 0x58 + (longlong)piVar6))) &&
                           (iVar15 = 0, 0 < *(int *)(lVar14 + 0x5c + (longlong)piVar6))) {
                          do {
                            FUN_140045870(*(uint *)((longlong)window_lock + 0x26),-1,
                                          *(int *)(lVar14 + 0x54 + (longlong)piVar6),
                                          *(int *)(lVar14 + 0x58 + (longlong)piVar6) + iVar15);
                            return_value = extraout_EAX;
                            if (extraout_EAX != 0) goto LAB_14004e55f;
                            iVar15 = iVar15 + 1;
                          } while (iVar15 < *(int *)(lVar14 + 0x5c + (longlong)piVar6));
                        }
                        GlobalUnlock(local_50);
                        uVar10 = uVar10 + 1;
                      } while ((int)uVar10 < 0x1e);
                      FUN_140048a3c(local_50);
                      iVar13 = iVar13 + 1;
                    } while (iVar13 < (int)param_6);
                  }
                }
                FUN_14003e2c4(window_handle,(longlong)window_lock,0x6c,0xffffffff,1);
                FUN_14003e2c4(window_handle,(longlong)window_lock,0x6a,0xffffffff,0);
                FUN_14003e2c4(window_handle,(longlong)window_lock,0x6e,0xffffffff,0);
              }
            }
            else {
              return_value = 0x2713;
            }
          }
        }
      }
    }
  }
LAB_14004e55f:
  if (DAT_140099090 != (HGLOBAL)0x0) {
    GlobalUnlock(DAT_140099090);
    GlobalFree(DAT_140099090);
    DAT_140099090 = (HGLOBAL)0x0;
  }
  if ((iVar11 != 0) && (opened_file != (uint *)0xffffffffffffffff)) {
    CloseHandle(opened_file);
  }
  if (return_value == 0) {
    if (DAT_1400980b4 == 0) {
      FUN_1400571b0((longlong)window_lock);
    }
    return_value = FUN_140053960(window_handle,(longlong)window_lock,param_4);
    if (return_value == 0) {
      if (DAT_1400980b4 != 0) {
        return_value = FUN_140055e48(window_handle,(longlong)window_lock);
      }
    }
    else if (return_value != 0xffffffff) {
      return_value = 0x5e3;
    }
  }
  if (DAT_140099078 != (HGLOBAL)0x0) {
    GlobalUnlock(DAT_140099078);
    GlobalFree(DAT_140099078);
    DAT_140099078 = (HGLOBAL)0x0;
  }
  if (return_value != 0) {
    UVar12 = return_value;
    if (0x31 < return_value - 0x5dd) {
      if (return_value == 0xffffffff) {
        UVar12 = 0;
      }
      else {
        UVar12 = 0x60;
        if (return_value != 0x67) {
          UVar12 = 7;
        }
      }
    }
    pHVar5 = GetParent(window_handle);
    ShowWindow(pHVar5,0);
    if ((UVar12 != 0) && (param_5 != 0)) {
      FUN_14005738c(UVar12);
    }
  }
  if ((*(uint *)((longlong)window_lock + 0x22) & 1) != 0) {
    *(uint *)((longlong)window_lock + 0x22) = *(uint *)((longlong)window_lock + 0x22) ^ 1;
  }
  GlobalUnlock(local_48);
  FUN_14007a020(2,0);
  SetCursor(DAT_1400baa20);
  some_thing_global = 0;
  return (ulonglong)return_value;
}


```

is the actual parse function...

0x4e2dc is the actual offset of the load function...

The parse function is at 0x4e2DC





Let's see what we can do...

Ok, so my setup now sort of seems to work. The fuzzer runs correctly, but it just opens the windows and then closes the window, but it takes many seconds to finish.

Now, the thing is that the same function which also parses the file also does the window bullshit fuck, so therefore, we may need to patch some of the window calls out.

```


ulonglong buffer_load(HWND window_handle,LPCSTR original_filename,int param_3,int param_4,
                     int param_5,uint param_6)

{
  undefined8 *puVar1;
  uint extraout_EAX;
  uint *window_lock;
  ulonglong uVar2;
  undefined8 uVar3;
  LPVOID pvVar4;
  HWND pHVar5;
  HGLOBAL hMem;
  int *piVar6;
  undefined4 *puVar7;
  undefined *puVar8;
  uint *maybe_buffer;
  uint return_value;
  uint uVar9;
  int iVar10;
  UINT UVar11;
  int somecheckvar;
  uint *opened_file;
  longlong lVar12;
  int iVar13;
  int local_58;
  uint handle_copy;
  HGLOBAL local_50;
  HGLOBAL local_48;

  opened_file = (uint *)0xffffffffffffffff;
  handle_copy = 0;
  DAT_140099090 = (HGLOBAL)0x0;
  somecheckvar = 1;
  DAT_14009908c = 0;
  local_58 = 1;
  DAT_1400980b4 = 1;
  DAT_140099088 = 0;
  DAT_140099078 = (HGLOBAL)0x0;
  DAT_140099070 = 0;
  DAT_14009906c = 0;
  DAT_1400990a0 = 0;
  if ((param_6 == 0) || (DAT_140099068 = somecheckvar, (DAT_1400babf6 & 0x400) == 0)) {
    DAT_140099068 = 0;
  }
  SetCursor(DAT_1400baa28);
  puVar8 = &DAT_00000008;
  some_thing_global = 1;
  local_48 = (HGLOBAL)GetWindowLongPtrA(window_handle,8);
  if (local_48 == (HGLOBAL)0x0) {
    return 1;
  }
  window_lock = (uint *)GlobalLock(local_48);
  *(undefined4 *)((longlong)window_lock + 0x56) = 5000;
  *(undefined4 *)((longlong)window_lock + 0x5a) = 5000;
  *(undefined4 *)((longlong)window_lock + 0x9a) = 10;
  *(undefined4 *)((longlong)window_lock + 0x9e) = 10;
  uVar2 = FUN_140042714((longlong)window_lock,puVar8,*(int *)((longlong)window_lock + 0xf6));
  return_value = (uint)uVar2;
  iVar10 = somecheckvar;
  if (return_value == 0) {
    puVar7 = &DAT_1400bb404;
    do {
      puVar7[-1] = (int)uVar2;
      return_value = (int)uVar2 + 1;
      uVar2 = (ulonglong)return_value;
      *puVar7 = 5;
      puVar7 = puVar7 + 2;
    } while ((int)return_value < 0x1e);
    puVar1 = (undefined8 *)((longlong)window_lock + 0x1da);
    uVar3 = FUN_1400470e4(*(uint *)((longlong)window_lock + 0x26),100,0x68,puVar1);
    return_value = (uint)uVar3;
    if (return_value == 0) {
      pvVar4 = GlobalLock((HGLOBAL)*puVar1);
      *(undefined8 *)((longlong)pvVar4 + 0x10) = 0;
      *(undefined8 *)((longlong)pvVar4 + 0x20) = 0;
      *(undefined4 *)((longlong)pvVar4 + 0x28) = 0;
      *(undefined8 *)((longlong)pvVar4 + 0x34) = 0;
      FUN_140048a3c((HGLOBAL)*puVar1);
      GlobalUnlock((HGLOBAL)*puVar1);
      uVar2 = FUN_140049608(*(uint *)((longlong)window_lock + 0x26),0x67);
      return_value = (uint)uVar2;
      if (return_value == 0) {
        uVar2 = FUN_140049608(*(uint *)((longlong)window_lock + 0x26),0x68);
        return_value = (uint)uVar2;
        if (return_value == 0) {
          uVar2 = FUN_140049608(*(uint *)((longlong)window_lock + 0x26),0x65);
          if ((int)uVar2 != 0) {
            return uVar2;
          }
          uVar2 = FUN_140049608(*(uint *)((longlong)window_lock + 0x26),0x66);
          if ((int)uVar2 != 0) {
            return uVar2;
          }
          DAT_140099078 = GlobalAlloc(0x42,29000);
          return_value = ~-(uint)(DAT_140099078 != (HGLOBAL)0x0) & 0x2714;
          if (DAT_140099078 != (HGLOBAL)0x0) {
            DAT_140099080 = GlobalLock(DAT_140099078);
            pHVar5 = GetParent(window_handle);
            hMem = (HGLOBAL)GetWindowLongPtrA(pHVar5,0);
            iVar13 = somecheckvar;
            if (hMem != (HGLOBAL)0x0) {
              piVar6 = (int *)GlobalLock(hMem);
              if ((*piVar6 == 0) &&
                 (maybe_buffer = *(uint **)(piVar6 + 0x84),
                 maybe_buffer != (uint *)0xffffffffffffffff)) {
                SetFilePointer(maybe_buffer,0,(PLONG)0x0,0);
                local_58 = 0;
                opened_file = maybe_buffer;
                iVar13 = 0;
              }
              GlobalUnlock(hMem);
            }
            iVar10 = local_58;
            if ((iVar13 == 0) ||
               (opened_file = (uint *)create_file_bullshit(original_filename,0),
               opened_file != (uint *)0xffffffffffffffff)) {
              return_value = filehandle_crc_check(opened_file);
              iVar13 = somecheckvar;
              if (return_value == 0) {
                do {
                  maybe_buffer = &handle_copy;
                  return_value = FUN_14005333c(opened_file,maybe_buffer,&param_6);
                  if (return_value != 0) goto LAB_14004e55f;
                  if (handle_copy == 0x4003) {
                    if (somecheckvar != 0) {
                      return_value = 0x5dd;
                      goto LAB_14004e55f;
                    }
                    if (iVar13 != 0) {
                      maybe_buffer = window_lock;
                      return_value = maybe_load_data(window_handle,(longlong)window_lock,opened_f ile
                                                    );
                    }
                    iVar13 = 0;
LAB_14004e655:
                    if (return_value != 0) goto LAB_14004e55f;
                  }
                  else if (handle_copy == 0x4005) {
                    maybe_buffer = opened_file;
                    return_value = FUN_14004eb64((longlong)window_lock,opened_file);
                    somecheckvar = 0;
                    goto LAB_14004e655;
                  }
                } while (handle_copy != 0x6001);
                if (hMem != (HGLOBAL)0x0) {
                  pvVar4 = GlobalLock(hMem);
                  *(uint *)((longlong)pvVar4 + 0x228) = (uint)(DAT_1400980b4 == 0);
                  GlobalUnlock(hMem);
                }
                if (param_3 != 0) {
                  uVar2 = maybe_load_more((longlong)window_lock,maybe_buffer,1);
                  return_value = (uint)uVar2;
                  if (return_value != 0) goto LAB_14004e55f;
                  uVar2 = FUN_140049480(*(uint *)((longlong)window_lock + 0x26),0x66,(int *)&para m_6
                                       );
                  return_value = (uint)uVar2;
                  if (return_value != 0) goto LAB_14004e55f;
                  somecheckvar = 0;
                  if (0 < (int)param_6) {
                    do {
                      uVar2 = FUN_14004952c(*(uint *)((longlong)window_lock + 0x26),0x66,
                                            somecheckvar,(int *)&handle_copy);
                      return_value = (uint)uVar2;
                      if ((return_value != 0) ||
                         (return_value = FUN_140047020(*(uint *)((longlong)window_lock + 0x26),0x 66,
                                                       handle_copy,&local_50), return_value != 0))
                      goto LAB_14004e55f;
                      uVar9 = 0;
                      do {
                        piVar6 = (int *)FUN_14007ac74(local_50,uVar9);
                        if ((((piVar6 != (int *)0x0) && (*piVar6 == 1)) &&
                            (lVar12 = (longlong)piVar6[2],
                            -1 < *(int *)(lVar12 + 0x58 + (longlong)piVar6))) &&
                           (iVar13 = 0, 0 < *(int *)(lVar12 + 0x5c + (longlong)piVar6))) {
                          do {
                            FUN_140045870(*(uint *)((longlong)window_lock + 0x26),-1,
                                          *(int *)(lVar12 + 0x54 + (longlong)piVar6),
                                          *(int *)(lVar12 + 0x58 + (longlong)piVar6) + iVar13);
                            return_value = extraout_EAX;
                            if (extraout_EAX != 0) goto LAB_14004e55f;
                            iVar13 = iVar13 + 1;
                          } while (iVar13 < *(int *)(lVar12 + 0x5c + (longlong)piVar6));
                        }
                        GlobalUnlock(local_50);
                        uVar9 = uVar9 + 1;
                      } while ((int)uVar9 < 0x1e);
                      FUN_140048a3c(local_50);
                      somecheckvar = somecheckvar + 1;
                    } while (somecheckvar < (int)param_6);
                  }
                }
                FUN_14003e2c4(window_handle,(longlong)window_lock,0x6c,0xffffffff,1);
                FUN_14003e2c4(window_handle,(longlong)window_lock,0x6a,0xffffffff,0);
                FUN_14003e2c4(window_handle,(longlong)window_lock,0x6e,0xffffffff,0);
              }
            }
            else {
              return_value = 0x2713;
            }
          }
        }
      }
    }
  }
LAB_14004e55f:
  if (DAT_140099090 != (HGLOBAL)0x0) {
    GlobalUnlock(DAT_140099090);
    GlobalFree(DAT_140099090);
    DAT_140099090 = (HGLOBAL)0x0;
  }
  if ((iVar10 != 0) && (opened_file != (uint *)0xffffffffffffffff)) {
    CloseHandle(opened_file);
  }
  if (return_value == 0) {
    if (DAT_1400980b4 == 0) {
      FUN_1400571b0((longlong)window_lock);
    }
    return_value = FUN_140053960(window_handle,(longlong)window_lock,param_4);
    if (return_value == 0) {
      if (DAT_1400980b4 != 0) {
        return_value = FUN_140055e48(window_handle,(longlong)window_lock);
      }
    }
    else if (return_value != 0xffffffff) {
      return_value = 0x5e3;
    }
  }
  if (DAT_140099078 != (HGLOBAL)0x0) {
    GlobalUnlock(DAT_140099078);
    GlobalFree(DAT_140099078);
    DAT_140099078 = (HGLOBAL)0x0;
  }
  if (return_value != 0) {
    UVar11 = return_value;
    if (0x31 < return_value - 0x5dd) {
      if (return_value == 0xffffffff) {
        UVar11 = 0;
      }
      else {
        UVar11 = 0x60;
        if (return_value != 0x67) {
          UVar11 = 7;
        }
      }
    }
    pHVar5 = GetParent(window_handle);
    ShowWindow(pHVar5,0);
    if ((UVar11 != 0) && (param_5 != 0)) {
      FUN_14005738c(UVar11);
    }
  }
  if ((*(uint *)((longlong)window_lock + 0x22) & 1) != 0) {
    *(uint *)((longlong)window_lock + 0x22) = *(uint *)((longlong)window_lock + 0x22) ^ 1;
  }
  GlobalUnlock(local_48);
  FUN_14007a020(2,0);
  SetCursor(DAT_1400baa20);
  some_thing_global = 0;
  return (ulonglong)return_value;
}


```


 cmake -A x64 .. -DDynamoRIO_DIR=C:\Users\elsku\dynamorio2\DynamoRIO-Windows-11.3.0-1\cmake -DINTELPT=1 -DUSE_COLOR=1

cmake --build . --config Release
4D6DC

0x4e2DC


658c0

the original shit was 0x4e2DC

1400658c0

C:\Users\elsku\winafl\winafl\build\bin\Release\afl-fuzz.exe -i c:\Users\elsku\inputs -o c:\Users\elsku\outputs -D C:\Users\elsku\dynamorio2\DynamoRIO-Windows-11.3.0-1\bin64 -I 40000  -debug -t 4000 -f test.opx -- -coverage_module ORGCHART.EXE -fuzz_iterations 1000 -persistence_mode in_app -target_module ORGCHART.EXE -verbose 100 -target_offset 0x4e2DC -nargs 6 -call_convention fastcall -- "C:\Program Files\Microsoft Office\root\Office16\ORGCHART.EXE" "@@"


So the fucking target function actually spawns a thread inside of it. Holy shit this is annoying to debug...

Here is the complete call stack:

```

Säikeen tunnist Osoite           Paluun kohde     Paluun lähde     Kok Muistialue   Kommentti
29016 - Pääsäie
                00000013925AE3C8 00007FFBB4FA4F78 00007FFBDEF744D0 40  Järjestelmä  kernel32.CreateThread
                00000013925AE408 00007FFBB4F909B4 00007FFBB4FA4F78 90  Järjestelmä  winspool.Ordinal#361+B8
                00000013925AE498 00007FFBDD363324 00007FFBB4F909B4 70  Järjestelmä  winspool.DocumentEvent+44
                00000013925AE508 00007FFBDD2FEF45 00007FFBDD363324 350 Järjestelmä  gdi32full.DocumentEventEx+114
                00000013925AE858 00007FFBDD324717 00007FFBDD2FEF45 80  Järjestelmä  gdi32full.hdcCreateDCW+195
                00000013925AE8D8 00007FFBDD323B21 00007FFBDD324717 40  Järjestelmä  gdi32full.SetBitmapDimensionEx+147
                00000013925AE918 00007FF79ACCDBD8 00007FFBDD323B21 310 Käyttäjäalue gdi32full.CreateICA+11
                00000013925AEC28 00007FF79ACB40D6 00007FF79ACCDBD8 130 Käyttäjäalue orgchart.00007FF79ACCDBD8
                00000013925AED58 00007FF79ACB52A0 00007FF79ACB40D6 6C0 Käyttäjäalue orgchart.00007FF79ACB40D6
                00000013925AF418 00007FF79ACB5B4E 00007FF79ACB52A0 40  Käyttäjäalue orgchart.00007FF79ACB52A0
                00000013925AF458 00007FF79ACB5C9F 00007FF79ACB5B4E 150 Käyttäjäalue orgchart.00007FF79ACB5B4E
                00000013925AF5A8 00007FF79ACA8D0C 00007FF79ACB5C9F 1D0 Käyttäjäalue orgchart.00007FF79ACB5C9F
                00000013925AF778 00007FF79ACDD472 00007FF79ACA8D0C 40  Käyttäjäalue orgchart.00007FF79ACA8D0C
                00000013925AF7B8 00007FFBDEF7259D 00007FF79ACDD472 30  Järjestelmä  orgchart.00007FF79ACDD472
                00000013925AF7E8 00007FFBDFFCAF38 00007FFBDEF7259D 80  Järjestelmä  kernel32.BaseThreadInitThunk+1D
                00000013925AF868 0000000000000000 00007FFBDFFCAF38     Käyttäjäalue ntdll.RtlUserThreadStart+28
19816
                0000001392DFF848 00007FFBDFFA586E 00007FFBE0013FF4 2E0 Järjestelmä  ntdll.NtWaitForWorkViaWorkerFactory+14
                0000001392DFFB28 00007FFBDEF7259D 00007FFBDFFA586E 30  Järjestelmä  ntdll.RtlClearThreadWorkOnBehalfTicket+35E
                0000001392DFFB58 00007FFBDFFCAF38 00007FFBDEF7259D 80  Järjestelmä  kernel32.BaseThreadInitThunk+1D
                0000001392DFFBD8 0000000000000000 00007FFBDFFCAF38     Käyttäjäalue ntdll.RtlUserThreadStart+28
2568
                00000013928FF518 00007FFBDFFA586E 00007FFBE0013FF4 2E0 Järjestelmä  ntdll.NtWaitForWorkViaWorkerFactory+14
                00000013928FF7F8 00007FFBDEF7259D 00007FFBDFFA586E 30  Järjestelmä  ntdll.RtlClearThreadWorkOnBehalfTicket+35E
                00000013928FF828 00007FFBDFFCAF38 00007FFBDEF7259D 80  Järjestelmä  kernel32.BaseThreadInitThunk+1D
                00000013928FF8A8 0000000000000000 00007FFBDFFCAF38     Käyttäjäalue ntdll.RtlUserThreadStart+28
4408
                00000013929FF868 00007FFBDFFA586E 00007FFBE0013FF4 2E0 Järjestelmä  ntdll.NtWaitForWorkViaWorkerFactory+14
                00000013929FFB48 00007FFBDEF7259D 00007FFBDFFA586E 30  Järjestelmä  ntdll.RtlClearThreadWorkOnBehalfTicket+35E
                00000013929FFB78 00007FFBDFFCAF38 00007FFBDEF7259D 80  Järjestelmä  kernel32.BaseThreadInitThunk+1D
                00000013929FFBF8 0000000000000000 00007FFBDFFCAF38     Käyttäjäalue ntdll.RtlUserThreadStart+28
1712
                0000001392CFF508 00007FFBDFFA586E 00007FFBE0013FF4 2E0 Järjestelmä  ntdll.NtWaitForWorkViaWorkerFactory+14
                0000001392CFF7E8 00007FFBDEF7259D 00007FFBDFFA586E 30  Järjestelmä  ntdll.RtlClearThreadWorkOnBehalfTicket+35E
                0000001392CFF818 00007FFBDFFCAF38 00007FFBDEF7259D 80  Järjestelmä  kernel32.BaseThreadInitThunk+1D
                0000001392CFF898 0000000000000000 00007FFBDFFCAF38     Käyttäjäalue ntdll.RtlUserThreadStart+28
6960
                0000001392AFF518 00007FFBDFFA586E 00007FFBE0013FF4 2E0 Järjestelmä  ntdll.NtWaitForWorkViaWorkerFactory+14
                0000001392AFF7F8 00007FFBDEF7259D 00007FFBDFFA586E 30  Järjestelmä  ntdll.RtlClearThreadWorkOnBehalfTicket+35E
                0000001392AFF828 00007FFBDFFCAF38 00007FFBDEF7259D 80  Järjestelmä  kernel32.BaseThreadInitThunk+1D
                0000001392AFF8A8 0000000000000000 00007FFBDFFCAF38     Käyttäjäalue ntdll.RtlUserThreadStart+28
29272
                0000001392BFF518 00007FFBDD7B6849 00007FFBE0010EF4 2E0 Järjestelmä  ntdll.NtWaitForMultipleObjects+14
                0000001392BFF7F8 00007FFBDE0807AD 00007FFBDD7B6849 2A0 Järjestelmä  kernelbase.WaitForMultipleObjectsEx+E9
                0000001392BFFA98 00007FFBDE08061A 00007FFBDE0807AD 50  Järjestelmä  combase.CoFreeUnusedLibrariesEx+82D
                0000001392BFFAE8 00007FFBDE08040F 00007FFBDE08061A 80  Järjestelmä  combase.CoFreeUnusedLibrariesEx+69A
                0000001392BFFB68 00007FFBDE080829 00007FFBDE08040F 30  Järjestelmä  combase.CoFreeUnusedLibrariesEx+48F
                0000001392BFFB98 00007FFBDEF7259D 00007FFBDE080829 30  Järjestelmä  combase.CoFreeUnusedLibrariesEx+8A9
                0000001392BFFBC8 00007FFBDFFCAF38 00007FFBDEF7259D 80  Järjestelmä  kernel32.BaseThreadInitThunk+1D
                0000001392BFFC48 0000000000000000 00007FFBDFFCAF38     Käyttäjäalue ntdll.RtlUserThreadStart+28


```


We are calling the CreateICA function from this function here:

```


void FUN_14007d9fc(LPCSTR param_1,HGLOBAL param_2,int *param_3,int *param_4,int param_5,
                  undefined4 *param_6,undefined8 param_7,int param_8)

{
  BYTE BVar1;
  HGLOBAL hMem;
  int *piVar2;
  char cVar3;
  undefined2 uVar4;
  int iVar5;
  BOOL BVar6;
  LONG LVar7;
  HDC pHVar8;
  HDC pHVar9;
  undefined8 *puVar10;
  HDC__ *pHVar11;
  PDEVMODEA pDevModeOutput;
  PDEVMODEA p_Var12;
  HDC__ *pHVar13;
  undefined2 uVar14;
  longlong lVar15;
  PDEVMODEA p_Var16;
  int iVar17;
  HDC lpString1;
  HDC pHVar19;
  undefined auStackY_308 [32];
  HANDLE local_2d8;
  int local_2d0;
  HGLOBAL local_2c8;
  int *local_2c0;
  int *local_2b8;
  HDC__ *local_2b0;
  undefined8 local_2a8;
  undefined8 uStack_2a0;
  undefined8 local_298;
  undefined8 uStack_290;
  undefined8 local_288;
  undefined8 uStack_280;
  undefined8 local_278;
  undefined8 uStack_270;
  undefined8 local_268;
  undefined8 uStack_260;
  undefined8 local_258;
  undefined8 uStack_250;
  undefined8 local_248;
  undefined8 uStack_240;
  undefined4 local_238;
  undefined4 uStack_234;
  undefined4 uStack_230;
  undefined4 uStack_22c;
  undefined8 local_228;
  undefined8 uStack_220;
  undefined8 local_218;
  undefined4 local_210;
  _devicemodeA local_208;
  HDC__ local_168 [68];
  ulonglong local_58;
  HDC pHVar18;

  local_58 = DAT_140098000 ^ (ulonglong)auStackY_308;
  local_2c8 = param_2;
  local_2c0 = param_3;
  local_2b8 = param_4;
  memset(&local_208,0,0x9c);
  memset(&local_2a8,0,0x9c);
  pHVar9 = (HDC)0x0;
  local_2b0 = (HDC__ *)0x0;
  local_2d0 = 0;
  local_2d8 = (HANDLE)0x0;
  iVar5 = lstrlenA(param_1);
  if (iVar5 == 0) {
    GetProfileStringA("windows","device","",param_1,0x105);
    *param_6 = 1;
    param_5 = 2;
  }
  iVar5 = lstrlenA(param_1);
  pHVar18 = (HDC)0x0;
  iVar17 = 0;
  lpString1 = pHVar9;
  if (iVar5 == 0) {
LAB_14007dc7f:
    GetProfileStringA("windows","device","",param_1,0x105);
    iVar5 = lstrlenA(param_1);
    param_5 = (iVar5 != 0) + 1;
LAB_14007dcb8:
    pHVar9 = (HDC)0x0;
    if (param_2 != (HGLOBAL)0x0) {
      puVar10 = (undefined8 *)GlobalLock(param_2);
      if (param_5 < 1) {
        if (*(short *)((longlong)puVar10 + 0x34) < 0x1a) {
          *(undefined2 *)((longlong)puVar10 + 0x34) = 100;
        }
      }
      else {
        *(undefined *)puVar10 = 0;
        *(undefined2 *)((longlong)puVar10 + 0x3e) = 1;
        *(undefined4 *)((longlong)puVar10 + 0x22) = 0x9c0000;
        *(undefined2 *)((longlong)puVar10 + 0x26) = 0;
        *(undefined4 *)((longlong)puVar10 + 0x36) = 0x80001;
        *(undefined4 *)((longlong)puVar10 + 0x3a) = 0x1fffc;
        if (param_8 != 0) {
          *(short *)((longlong)puVar10 + 0x2c) = (short)param_8;
        }
        iVar5 = DAT_1400992d0;
        if (param_5 == 1) {
          *(undefined2 *)(puVar10 + 4) = 0x401;
          if (iVar5 == 0) {
            uVar4 = 0xb9a;
            uVar14 = 0x834;
          }
          else {
            uVar4 = 0x86f;
            uVar14 = 0xaea;
          }
          *(undefined2 *)(puVar10 + 6) = uVar14;
          *(undefined2 *)((longlong)puVar10 + 0x32) = uVar4;
          *(undefined2 *)((longlong)puVar10 + 0x2c) = 2;
          if (iVar5 == 0) {
            uVar4 = 9;
          }
          else {
            uVar4 = 1;
          }
          *(undefined2 *)((longlong)puVar10 + 0x2e) = uVar4;
          *(undefined2 *)((longlong)puVar10 + 0x34) = 100;
        }
        else {
          local_2a8 = *puVar10;
          uStack_2a0 = puVar10[1];
          local_298 = puVar10[2];
          uStack_290 = puVar10[3];
          local_288 = puVar10[4];
          uStack_280 = puVar10[5];
          local_278 = puVar10[6];
          uStack_270 = puVar10[7];
          local_268 = puVar10[8];
          uStack_260 = puVar10[9];
          local_258 = puVar10[10];
          uStack_250 = puVar10[0xb];
          local_248 = puVar10[0xc];
          uStack_240 = puVar10[0xd];
          local_218 = puVar10[0x12];
          local_238 = *(undefined4 *)(puVar10 + 0xe);
          uStack_234 = *(undefined4 *)((longlong)puVar10 + 0x74);
          uStack_230 = *(undefined4 *)(puVar10 + 0xf);
          uStack_22c = *(undefined4 *)((longlong)puVar10 + 0x7c);
          local_228 = puVar10[0x10];
          uStack_220 = puVar10[0x11];
          local_210 = *(undefined4 *)(puVar10 + 0x13);
        }
        *(undefined4 *)(puVar10 + 5) = 0x713;
      }
      iVar5 = lstrlenA(param_1);
      if (iVar5 != 0) {
        lVar15 = 0x106;
        pHVar13 = local_168;
        do {
          if ((lVar15 == -0x7ffffef8) ||
             (cVar3 = *(char *)((longlong)pHVar13 + ((longlong)param_1 - (longlong)local_168)),
             cVar3 == '\0')) break;
          *(char *)&pHVar13->unused = cVar3;
          pHVar13 = (HDC__ *)((longlong)&pHVar13->unused + 1);
          lVar15 = lVar15 + -1;
        } while (lVar15 != 0);
        lpString1 = (HDC)0x0;
        iVar5 = 0;
        pHVar11 = (HDC__ *)((longlong)&pHVar13[-1].unused + 3);
        if (lVar15 != 0) {
          pHVar11 = pHVar13;
        }
        pHVar9 = local_168;
        *(undefined *)&pHVar11->unused = 0;
        local_2b0 = local_168;
        pHVar8 = lpString1;
        pHVar18 = lpString1;
        if ((char)local_168[0].unused == '\0') {
LAB_14007dea9:
          iVar5 = 0x2714;
        }
        else {
          do {
            if ((char)local_168[0].unused == ',') {
              *(undefined *)&pHVar9->unused = 0;
              do {
                pHVar9 = (HDC)((longlong)&pHVar9->unused + 1);
              } while (*(char *)&pHVar9->unused == ' ');
              pHVar18 = pHVar9;
              if (pHVar8 != (HDC)0x0) {
                lpString1 = pHVar9;
                pHVar18 = pHVar8;
              }
            }
            else {
              pHVar9 = (HDC)CharNextA((LPCSTR)pHVar9);
              pHVar18 = pHVar8;
            }
            local_168[0].unused._0_1_ = *(char *)&pHVar9->unused;
            pHVar8 = pHVar18;
          } while ((char)local_168[0].unused != '\0');
          if ((pHVar18 == (HDC)0x0) || (lpString1 == (HDC)0x0)) goto LAB_14007dea9;
        }
        if (((iVar5 == 0) && (iVar5 = lstrcmpiA((LPCSTR)lpString1,"None"), iVar5 != 0)) &&
           (BVar6 = OpenPrinterA((LPSTR)local_168,&local_2d8,(LPPRINTER_DEFAULTSA)0x0), BVar6 ==  0))
        {
          local_2d8 = (HANDLE)0x0;
        }
        pHVar9 = (HDC)0x0;
        param_2 = local_2c8;
        if (local_2d8 != (HANDLE)0x0) {
          LVar7 = DocumentPropertiesA((HWND)0x0,local_2d8,(LPSTR)pHVar18,(PDEVMODEA)0x0,
                                      (PDEVMODEA)0x0,0);
          hMem = local_2c8;
          GlobalUnlock(local_2c8);
          GlobalReAlloc(hMem,(longlong)LVar7,0);
          pDevModeOutput = (PDEVMODEA)GlobalLock(hMem);
          lVar15 = 0x20;
          p_Var16 = pDevModeOutput;
          do {
            if ((lVar15 == -0x7fffffde) ||
               (BVar1 = *(BYTE *)(((longlong)local_168 - (longlong)pDevModeOutput) +
                                 (longlong)p_Var16), BVar1 == '\0')) break;
            p_Var16->dmDeviceName[0] = BVar1;
            p_Var16 = (PDEVMODEA)(p_Var16->dmDeviceName + 1);
            lVar15 = lVar15 + -1;
          } while (lVar15 != 0);
          p_Var12 = (PDEVMODEA)((longlong)&p_Var16[-1].dmPanningHeight + 3);
          if (lVar15 != 0) {
            p_Var12 = p_Var16;
          }
          p_Var12->dmDeviceName[0] = '\0';
          if (param_5 == 0) {
            memmove(&local_208,pDevModeOutput,0x9c);
          }
          else {
            DocumentPropertiesA((HWND)0x0,local_2d8,(LPSTR)pHVar18,pDevModeOutput,(PDEVMODEA)0x0 ,2);
            memmove(&local_208,pDevModeOutput,0x9c);
            if (param_8 != 0) {
              local_208.field6_0x2c.field0.dmOrientation = (short)param_8;
            }
            if (param_5 == 1) {
              local_208.field6_0x2c.field0.dmOrientation = 2;
              local_208.dmFields = 1;
            }
            else if (param_5 == 2) {
              local_208.field6_0x2c.field0.dmOrientation = uStack_280._4_2_;
              local_208.field6_0x2c.field0.dmPaperSize = uStack_280._6_2_;
              local_208.dmFields = 3;
            }
            if ((((pDevModeOutput->field6_0x2c).field0.dmPaperLength != 0) &&
                ((pDevModeOutput->field6_0x2c).field0.dmPaperLength < 0x3f8)) ||
               (((pDevModeOutput->field6_0x2c).field0.dmPaperWidth != 0 &&
                ((pDevModeOutput->field6_0x2c).field0.dmPaperWidth < 0x3f8)))) {
              local_208.dmFields = local_208.dmFields | 2;
              local_208.field6_0x2c.field0.dmPaperSize = 1;
            }
            local_208.dmSize = 0x9c;
            local_208.dmDriverExtra = 0;
          }
          DocumentPropertiesA((HWND)0x0,local_2d8,(LPSTR)pHVar18,pDevModeOutput,&local_208,10);
          pDevModeOutput->dmFields = 0x713;
          pHVar9 = FUN_14007e14c((LPCSTR)pHVar18,(LPCSTR)local_168,(LPCSTR)lpString1,hMem);
          if (local_2d8 != (HANDLE)0x0) {
            ClosePrinter(local_2d8);
          }
          param_2 = local_2c8;
          FUN_14007d6c0(pHVar9,local_2c8,local_2b8,local_2c0);
          local_2d0 = 1;
        }
      }
      GlobalUnlock(param_2);
    }
LAB_14007e0d4:
    if ((param_5 != 1) && (pHVar9 != (HDC)0x0)) goto LAB_14007e124;
    if (local_2d0 == 0) {
      local_2c0[0] = 0;
      local_2c0[1] = 0;
      local_2c0[2] = 0;
      local_2c0[3] = 0;
      local_2b8[1] = 0x630;
      *local_2b8 = 0x4c8;
    }
  }
  else {
    pHVar13 = local_168;
    lVar15 = 0x106;
    do {
      if ((lVar15 == -0x7ffffef8) ||
         (cVar3 = *(char *)((longlong)pHVar13 + ((longlong)param_1 - (longlong)local_168)),
         cVar3 == '\0')) break;
      *(char *)&pHVar13->unused = cVar3;
      pHVar13 = (HDC__ *)((longlong)&pHVar13->unused + 1);
      lVar15 = lVar15 + -1;
    } while (lVar15 != 0);
    pHVar11 = (HDC__ *)((longlong)&pHVar13[-1].unused + 3);
    if (lVar15 != 0) {
      pHVar11 = pHVar13;
    }
    pHVar8 = local_168;
    *(undefined *)&pHVar11->unused = 0;
    local_2b0 = local_168;
    pHVar19 = pHVar18;
    cVar3 = (char)local_168[0].unused;
    if ((char)local_168[0].unused == '\0') {
LAB_14007db92:
      iVar17 = 0x2714;
    }
    else {
      do {
        if (cVar3 == ',') {
          *(undefined *)&pHVar8->unused = 0;
          do {
            pHVar8 = (HDC)((longlong)&pHVar8->unused + 1);
          } while (*(char *)&pHVar8->unused == ' ');
          pHVar18 = pHVar8;
          if (pHVar19 != (HDC)0x0) {
            lpString1 = pHVar8;
            pHVar18 = pHVar19;
          }
        }
        else {
          pHVar8 = (HDC)CharNextA((LPCSTR)pHVar8);
          pHVar18 = pHVar19;
        }
        cVar3 = *(char *)&pHVar8->unused;
        pHVar19 = pHVar18;
      } while (cVar3 != '\0');
      if ((pHVar18 == (HDC)0x0) || (lpString1 == (HDC)0x0)) goto LAB_14007db92;
    }
    if ((iVar17 != 0) || (iVar5 = lstrcmpiA((LPCSTR)lpString1,"None"), iVar5 == 0))
    goto LAB_14007dc7f;
    SetErrorMode(0x8000);
    pHVar8 = CreateICA((LPCSTR)pHVar18,(LPCSTR)local_168,(LPCSTR)lpString1,(DEVMODEA *)0x0);
    SetErrorMode(0);
    param_2 = local_2c8;
    if (pHVar8 == (HDC)0x0) goto LAB_14007dc7f;
    iVar5 = GetDeviceCaps(pHVar8,2);
    DeleteDC(pHVar8);
    param_2 = local_2c8;
    if (iVar5 == 4) goto LAB_14007e0d4;
    if (local_2c8 == (HGLOBAL)0x0) {
      param_5 = 2;
    }
    if (param_5 != 0) goto LAB_14007dcb8;
    pHVar9 = FUN_14007e14c((LPCSTR)pHVar18,(LPCSTR)local_168,(LPCSTR)lpString1,local_2c8);
    piVar2 = local_2b8;
    FUN_14007d6c0(pHVar9,param_2,local_2b8,local_2c0);
    if ((*piVar2 == 0x240) && (piVar2[1] == 0x240)) {
      param_5 = 1;
      DeleteDC(pHVar9);
      goto LAB_14007dcb8;
    }
  }
  if (pHVar9 == (HDC)0x0) {
    FUN_14007e14c((LPCSTR)0x0,(LPCSTR)local_2b0,(LPCSTR)lpString1,(HGLOBAL)0x0);
  }
LAB_14007e124:
  FUN_14008d510(local_58 ^ (ulonglong)auStackY_308);
  return;
}


```

Here is some documentation:

https://learn.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-createica

I am going to rename this function to createdrivericathing


Ok, so we call that function from:

```


void FUN_140063ae8(HWND param_1,uint param_2,int param_3)

{
  HWND pHVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  undefined4 uVar5;
  uint uVar6;
  HGLOBAL pvVar7;
  LPVOID pvVar8;
  ulonglong uVar9;
  HGLOBAL pvVar10;
  LPVOID pvVar11;
  longlong lVar12;
  SIZE_T SVar13;
  undefined2 *puVar14;
  HDC hdc;
  char cVar15;
  ulonglong uVar16;
  undefined8 uVar17;
  int *piVar18;
  HGLOBAL pvVar19;
  HGLOBAL hMem;
  undefined auStackY_128 [32];
  undefined4 in_stack_ffffffffffffff08;
  undefined4 in_stack_ffffffffffffff0c;
  undefined4 uVar20;
  undefined4 in_stack_ffffffffffffff14;
  undefined8 in_stack_ffffffffffffff18;
  HGLOBAL local_d8;
  HGLOBAL local_d0;
  HGLOBAL local_c8;
  longlong local_c0;
  HGLOBAL local_b8;
  HWND local_b0;
  HGLOBAL local_a8;
  HGLOBAL local_a0;
  HGLOBAL local_98;
  HGLOBAL local_90;
  HGLOBAL local_88;
  HGLOBAL local_80;
  longlong local_78 [2];
  tagRECT local_68;
  tagRECT local_58;
  ulonglong local_48;

  local_48 = DAT_140098000 ^ (ulonglong)auStackY_128;
  pvVar10 = (HGLOBAL)0x0;
  uVar16 = (ulonglong)param_2;
  local_a8 = (HGLOBAL)0x0;
  local_d0 = (HGLOBAL)0x0;
  local_d8 = (HGLOBAL)0x0;
  local_80 = (HGLOBAL)0x0;
  local_b8 = (HGLOBAL)0x0;
  local_98 = (HGLOBAL)0x0;
  pvVar19 = (HGLOBAL)0x0;
  local_88 = (HGLOBAL)0x0;
  local_c0 = 0;
  local_78[0] = 0;
  local_a0 = (HGLOBAL)0x0;
  local_78[1] = 0;
  local_b0 = param_1;
  pvVar7 = GlobalAlloc(2,0x428);
  local_c8 = pvVar7;
  if (pvVar7 != (HGLOBAL)0x0) {
    local_90 = GlobalAlloc(2,0x9c);
    hMem = pvVar10;
    if (((((local_90 != (HGLOBAL)0x0) &&
          (local_a0 = GlobalAlloc(0x42,4), hMem = pvVar19, local_a0 != (HGLOBAL)0x0)) &&
         (iVar2 = FUN_1400460a4(param_2,100,0x68,0x3c,(longlong *)&local_b8), iVar2 == 0)) &&
        ((iVar2 = FUN_1400460a4(param_2,100,0x6a,0x1a,(longlong *)&local_88), iVar2 == 0 &&
         (iVar2 = FUN_1400460a4(param_2,100,100,0x438,&local_c0), iVar2 == 0)))) &&
       ((iVar2 = FUN_1400460a4(param_2,100,0x6e,0xac,local_78), iVar2 == 0 &&
        (iVar2 = FUN_1400460a4(param_2,100,0x6f,0x14,local_78 + 1), iVar2 == 0)))) {
      pvVar8 = GlobalLock(local_b8);
      *(undefined8 *)((longlong)pvVar8 + 0x20) = 0;
      *(undefined4 *)((longlong)pvVar8 + 0x28) = 0;
      *(undefined8 *)((longlong)pvVar8 + 0x34) = 0;
      *(undefined8 *)((longlong)pvVar8 + 0x10) = 1;
      GlobalUnlock(local_b8);
      uVar9 = FUN_14007ad40(&local_a8);
      if (((int)uVar9 != 0) || (pvVar10 = GlobalAlloc(2,0), pvVar10 == (HGLOBAL)0x0))
      goto LAB_140063d96;
      iVar2 = 0;
      if ((param_3 == 5) || (((param_3 == 6 || (param_3 == 0x60)) || (param_3 == 99)))) {
        iVar2 = 1;
      }
      local_c0 = CONCAT44(local_c0._4_4_,iVar2);
      if ((iVar2 == 0) || ((DAT_1400babf6 & 0x100) == 0)) {
        iVar3 = FUN_140063ab4(100,0x67,&local_d8);
        iVar2 = DAT_1400bacf0;
        if (iVar3 == 0) goto LAB_140063d56;
LAB_140063d8e:
        local_d0 = local_d8;
LAB_140063d96:
        pvVar19 = pvVar10;
        if (local_a8 != (HGLOBAL)0x0) {
          GlobalFree(local_a8);
        }
      }
      else {
        iVar2 = FUN_140063ab4(100,0x71,&local_d8);
        if (iVar2 != 0) goto LAB_140063d8e;
        iVar2 = 1;
LAB_140063d56:
        iVar2 = FUN_140063ab4(0x67,iVar2,&local_d0);
        if (iVar2 != 0) goto LAB_140063d8e;
        iVar2 = FUN_140046144(param_2,0x67,0,(longlong)local_d0);
        if (iVar2 != 0) {
          GlobalFree(local_d0);
          goto LAB_140063d8e;
        }
        SetRect(&local_58,0,0,DAT_1400bac94,DAT_1400bac94);
        pvVar8 = GlobalLock(pvVar7);
        local_d0 = local_d8;
        *(undefined4 *)((longlong)pvVar8 + 0x22a) = DAT_1400bac8c;
        *(undefined4 *)((longlong)pvVar8 + 0x22e) = DAT_1400bacdc;
        *(undefined4 *)((longlong)pvVar8 + 0x232) = DAT_1400bacf4;
        *(undefined4 *)((longlong)pvVar8 + 0x236) = DAT_1400bace4;
        *(undefined4 *)((longlong)pvVar8 + 0x23a) = DAT_1400bace0;
        *(undefined4 *)((longlong)pvVar8 + 0x23e) = DAT_1400bacb0;
        *(undefined4 *)((longlong)pvVar8 + 0x242) = DAT_1400baca4;
        *(undefined4 *)((longlong)pvVar8 + 0x246) = DAT_1400baca8;
        *(undefined4 *)((longlong)pvVar8 + 0x24a) = DAT_1400bacac;
        *(undefined4 *)((longlong)pvVar8 + 0x276) = DAT_1400bac9c;
        *(undefined4 *)((longlong)pvVar8 + 0x27a) = DAT_1400bac98;
        *(undefined4 *)((longlong)pvVar8 + 0x27e) = 0;
        uVar20 = DAT_1400bac54;
        if (param_3 == 0x60) {
          uVar20 = 0xe;
        }
        *(undefined4 *)((longlong)pvVar8 + 0x282) = uVar20;
        *(undefined4 *)((longlong)pvVar8 + 0x286) = DAT_1400bac58;
        *(undefined4 *)((longlong)pvVar8 + 0x28a) = DAT_1400bac5c;
        *(undefined4 *)((longlong)pvVar8 + 0x266) = DAT_1400bacc8;
        *(undefined4 *)((longlong)pvVar8 + 0x26e) = DAT_1400baccc;
        *(undefined4 *)((longlong)pvVar8 + 0x26a) = DAT_1400bacd0;
        uVar20 = DAT_1400bacd8;
        *(undefined4 *)((longlong)pvVar8 + 0xf6) = 0xffffffff;
        *(HGLOBAL *)((longlong)pvVar8 + 0xde) = local_d8;
        *(undefined8 *)((longlong)pvVar8 + 0xea) = 0;
        *(undefined8 *)((longlong)pvVar8 + 0x21e) = 0;
        *(undefined8 *)((longlong)pvVar8 + 0x1e6) = 0;
        *(undefined4 *)((longlong)pvVar8 + 0x272) = uVar20;
        *(undefined4 *)((longlong)pvVar8 + 0xce) = 0;
        *(undefined8 *)((longlong)pvVar8 + 0xfe) = 0;
        *(undefined8 *)((longlong)pvVar8 + 0x1fa) = 0;
        *(undefined8 *)((longlong)pvVar8 + 0x212) = 0;
        *(undefined8 *)((longlong)pvVar8 + 0x206) = 0;
        *(undefined8 *)((longlong)pvVar8 + 0x2c2) = 0;
        *(undefined8 *)((longlong)pvVar8 + 0x2ca) = 0;
        *(HGLOBAL *)((longlong)pvVar8 + 0xba) = local_a0;
        *(LPCSTR)((longlong)pvVar8 + 0x2d2) = '\0';
        *(undefined4 *)((longlong)pvVar8 + 0x226) = 0;
        *(undefined8 *)((longlong)pvVar8 + 0x296) = 0;
        *(undefined4 *)((longlong)pvVar8 + 0x29e) = 0;
        *(undefined8 *)((longlong)pvVar8 + 0xd2) = 0;
        *(uint *)((longlong)pvVar8 + 0x26) = param_2;
        *(undefined4 *)((longlong)pvVar8 + 0x22) = 0x2800;
        *(undefined8 *)((longlong)pvVar8 + 0x28e) = 1;
        *(undefined4 *)((longlong)pvVar8 + 0x3a) = 1;
        *(undefined4 *)((longlong)pvVar8 + 0x2a2) = 1;
        *(undefined4 *)((longlong)pvVar8 + 0x2be) = DAT_1400bacd0;
        SetRect((LPRECT)((longlong)pvVar8 + 0x2a6),0,0,0,0);
        pvVar7 = local_90;
        *(undefined4 *)((longlong)pvVar8 + 0x3d8) = 0;
        *(undefined4 *)((longlong)pvVar8 + 0x3dc) = DAT_140098334;
        *(undefined4 *)((longlong)pvVar8 + 0x3e0) = DAT_1400983fc;
        *(undefined8 *)((longlong)pvVar8 + 0x3e4) = 0;
        *(undefined4 *)((longlong)pvVar8 + 0xfa) = DAT_1400bacd4;
        *(undefined8 *)((longlong)pvVar8 + 0x2b6) = 0;
        pvVar11 = GlobalLock(local_90);
        memmove(pvVar11,&DAT_1400bb364,0x9c);
        *(HGLOBAL *)((longlong)pvVar8 + 0xae) = pvVar7;
        GlobalUnlock(pvVar7);
        uVar20 = 0;
        local_d8 = (HGLOBAL)CONCAT44(local_d8._4_4_,1);
        lVar12 = createdrivericathing
                           ((LPCSTR)((longlong)pvVar8 + 0x2d2),pvVar7,
                            (int *)((longlong)pvVar8 + 0x8a),(int *)((longlong)pvVar8 + 0x66),1,
                            (undefined4 *)&local_d8,
                            CONCAT44(in_stack_ffffffffffffff0c,in_stack_ffffffffffffff08),0);
        *(longlong *)((longlong)pvVar8 + 0x21e) = lVar12;
        pvVar7 = local_c8;
        if (lVar12 == 0) goto LAB_140063d96;
        uVar4 = *(uint *)((longlong)pvVar8 + 0x22);
        if ((int)local_d8 == 0) {
          if ((uVar4 & 0x2000) != 0) {
            uVar4 = uVar4 ^ 0x2000;
            goto LAB_14006410a;
          }
        }
        else {
          uVar4 = uVar4 | 0x2000;
LAB_14006410a:
          *(uint *)((longlong)pvVar8 + 0x22) = uVar4;
        }
        pvVar19 = GlobalAlloc(0x42,4);
        pvVar7 = local_c8;
        local_98 = pvVar19;
        if (pvVar19 == (HGLOBAL)0x0) goto LAB_140063d96;
        *(HGLOBAL *)((longlong)pvVar8 + 0x1e6) = pvVar19;
        SVar13 = GlobalSize(pvVar19);
        iVar2 = FUN_1400460a4(param_2,100,0x69,SVar13 + 0x10,(longlong *)&local_d8);
        pvVar7 = local_c8;
        if (iVar2 != 0) goto LAB_140063d96;
        FUN_1400489d0(pvVar19,local_d8);
        FUN_140048a3c(local_d8);
        iVar2 = FUN_14007b578(*(HGLOBAL *)((longlong)pvVar8 + 0x1e6),DAT_1400990d0);
        iVar2 = FUN_14007b67c(local_a0,iVar2);
        pvVar7 = local_c8;
        if (iVar2 == -1) goto LAB_140063d96;
        *(int *)((longlong)pvVar8 + 0x27e) = iVar2;
        DAT_140098ee0 = *(undefined8 *)((longlong)pvVar8 + 0xba);
        DAT_140098ed8 = *(undefined8 *)((longlong)pvVar8 + 0x1e6);
        iVar2 = FUN_140062a10(param_2,local_b8,&local_80,(int *)&local_d8,1);
        pvVar19 = local_88;
        pvVar7 = local_c8;
        if (iVar2 != 0) goto LAB_140063d96;
        FUN_140048a3c(local_88);
        pvVar11 = GlobalLock(pvVar19);
        uVar5 = (int)local_d8;
        *(undefined2 *)((longlong)pvVar11 + 0x10) = 0x3ed;
        *(undefined4 *)((longlong)pvVar11 + 0x12) = 0;
        *(int *)((longlong)pvVar11 + 0x16) = (int)local_d8;
        GlobalUnlock(pvVar19);
        pvVar19 = local_80;
        *(HGLOBAL *)((longlong)pvVar8 + 0xea) = local_80;
        *(undefined4 *)((longlong)pvVar8 + 0xf6) = uVar5;
        if (local_80 != (HGLOBAL)0x0) {
          pvVar11 = GlobalLock(local_80);
          if (pvVar11 != (LPVOID)0x0) {
            *(ushort *)((longlong)pvVar11 + 0xe) = *(ushort *)((longlong)pvVar11 + 0xe) | 4;
          }
          GlobalUnlock(pvVar19);
        }
        if (((int)local_c0 != 0) && (((byte)DAT_1400babfa & 0x40) != 0)) {
          FUN_1400627c0(param_2,(longlong)pvVar8,local_b8);
        }
        iVar2 = FUN_140046144(param_2,100,0x67,*(longlong *)((longlong)pvVar8 + 0xde));
        pHVar1 = local_b0;
        pvVar7 = local_c8;
        if (iVar2 != 0) goto LAB_140063d96;
        local_d0 = (HGLOBAL)0x0;
        FUN_14003e2c4(local_b0,(longlong)pvVar8,0x6c,0xffffffff,1);
        pvVar7 = local_c8;
        *(undefined4 *)((longlong)pvVar8 + 0x1f6) = DAT_1400bac78;
        GlobalUnlock(local_c8);
        SetWindowLongPtrA(pHVar1,8,(LONG_PTR)pvVar7);
        if ((((param_3 == 2) || (param_3 == 4)) || (param_3 == 5)) ||
           (((param_3 == 7 || (param_3 == 8)) ||
            ((param_3 == 0x5b || ((param_3 == 0x5c || (param_3 == 0x5e)))))))) {
          local_c0 = CONCAT44(local_c0._4_4_,1);
          local_c8 = (HGLOBAL)CONCAT44(local_c8._4_4_,1);
        }
        else {
          iVar2 = FUN_1400279a8(pHVar1,param_2,pvVar19,1,1);
          if ((iVar2 != 0) ||
             (uVar9 = FUN_14002221c(pHVar1,param_2,DAT_1400bac78,pvVar19,0,1), (int)uVar9 != 0))
          goto LAB_140063d96;
          FUN_140079e78(2,32000);
          FUN_14007a020(2,0);
          pvVar8 = GlobalLock(pvVar19);
          local_c0 = CONCAT44(local_c0._4_4_,
                              *(int *)((longlong)pvVar8 + 0x24) - *(int *)((longlong)pvVar8 + 0x1c ))
          ;
          local_c8 = (HGLOBAL)CONCAT44(local_c8._4_4_,
                                       *(int *)((longlong)pvVar8 + 0x28) -
                                       *(int *)((longlong)pvVar8 + 0x20));
          GlobalUnlock(pvVar19);
        }
        if (pvVar19 != (HGLOBAL)0x0) {
          pvVar8 = GlobalLock(pvVar19);
          if ((pvVar8 != (LPVOID)0x0) && ((*(ushort *)((longlong)pvVar8 + 0xe) & 4) != 0)) {
            *(ushort *)((longlong)pvVar8 + 0xe) = *(ushort *)((longlong)pvVar8 + 0xe) ^ 4;
          }
          GlobalUnlock(pvVar19);
        }
        SetRect(&local_68,4,4,4,0);
        uVar4 = FUN_14004313c(pvVar10,&local_58.left,&local_68.left,0,0x420);
        if (((((uVar4 != 0) ||
              (uVar4 = FUN_14004313c(pvVar10,&local_58.left,&local_68.left,1,0x20), uVar4 != 0)) ||
             (uVar4 = FUN_14004313c(pvVar10,&local_58.left,&local_68.left,2,0x420), uVar4 != 0)) ||
            ((uVar4 = FUN_14004313c(pvVar10,&local_58.left,&local_68.left,3,0x420), uVar4 != 0 ||
             (uVar4 = FUN_14004313c(pvVar10,&local_58.left,&local_68.left,4,0x420), uVar4 != 0))) )
           || (uVar4 = FUN_14004313c(pvVar10,&local_58.left,&local_68.left,5,0x420), uVar4 != 0) )
        goto LAB_140063d96;
        puVar14 = (undefined2 *)GlobalLock(pvVar7);
        *(HGLOBAL *)(puVar14 + 0x69) = local_a8;
        *puVar14 = 0x3ed;
        *(HGLOBAL *)(puVar14 + 99) = pvVar10;
        *(undefined8 *)(puVar14 + 0x7f) = 0;
        *(undefined8 *)(puVar14 + 0xfd) = 0;
        *(uint *)(puVar14 + 0x13) = param_2;
        *(HGLOBAL *)(puVar14 + 0x75) = pvVar19;
        *(int *)(puVar14 + 0x7b) = (int)local_d8;
        *(int *)(puVar14 + 0x21) = (int)local_d8;
        *(HGLOBAL *)(puVar14 + 0xed) = local_b8;
        *(int *)(puVar14 + 0x27) = (int)local_c0;
        *(undefined8 *)(puVar14 + 0x15) = 3;
        *(undefined8 *)(puVar14 + 0x19) = 0;
        *(undefined4 *)(puVar14 + 0x1f) = 0;
        *(undefined8 *)(puVar14 + 0x23) = 0;
        *(undefined4 *)(puVar14 + 0x85) = 0;
        *(undefined4 *)(puVar14 + 0xc3) = 0;
        *(undefined4 *)(puVar14 + 0x29) = local_c8._0_4_;
        *(int *)(puVar14 + 0x3b) = (int)local_c0 / 2;
        *(undefined8 *)(puVar14 + 0x2b) = 0;
        *(undefined4 *)(puVar14 + 0x37) = 0x5a;
        *(undefined4 *)(puVar14 + 0x39) = 0x12;
        if ((*(int *)(puVar14 + 0x45) == 0) || (uVar5 = 0xe, *(int *)(puVar14 + 0x47) == 0)) {
          uVar5 = 0;
        }
        *(undefined4 *)(puVar14 + 0x51) = uVar5;
        *(undefined8 *)(puVar14 + 0x53) = 0;
        CopyRect((LPRECT)(puVar14 + 0x3d),(RECT *)&DAT_1400bac68);
        uVar4 = *(uint *)(puVar14 + 0x11);
        uVar6 = uVar4 | 2;
        *(uint *)(puVar14 + 0x11) = uVar6;
        cVar15 = (char)DAT_1400babf6;
        if ((DAT_1400babf6 & 4) != 0) {
          uVar6 = uVar4 | 6;
          *(uint *)(puVar14 + 0x11) = uVar6;
          cVar15 = (char)DAT_1400babf6;
        }
        if (cVar15 < '\0') {
          *(uint *)(puVar14 + 0x11) = uVar6 | 0x200;
        }
        *(undefined4 *)(puVar14 + 0x11) = 0x2602;
        iVar2 = FUN_140046144(param_2,100,0x65,*(longlong *)(puVar14 + 99));
        if (iVar2 != 0) goto LAB_140063d96;
        uVar17 = 100;
        pvVar19 = (HGLOBAL)0x0;
        pvVar10 = (HGLOBAL)0x0;
        iVar2 = FUN_140046144(param_2,100,0x66,*(longlong *)(puVar14 + 0x69));
        pHVar1 = local_b0;
        if (iVar2 != 0) goto LAB_140063d96;
        piVar18 = (int *)(puVar14 + 0x3d);
        local_a8 = (HGLOBAL)0x0;
        iVar2 = FUN_14002d200(uVar16,uVar17,piVar18,*(undefined8 *)(puVar14 + 0x37),
                              *(undefined8 *)(puVar14 + 0x2b),local_b0,param_2,
                              CONCAT44(in_stack_ffffffffffffff14,uVar20),in_stack_ffffffffffffff18 ,
                              (longlong *)(puVar14 + 0xfd));
        uVar4 = (uint)piVar18;
        if (iVar2 == 0) {
          if ((((param_3 != 2) && (param_3 != 4)) && (param_3 != 5)) &&
             ((((param_3 != 6 && (param_3 != 7)) &&
               ((param_3 != 8 && ((param_3 != 0x5b && (param_3 != 0x5c)))))) && (param_3 != 0x5e) )))
          {
            FUN_1400782bc((longlong)puVar14,0);
            pvVar19 = *(HGLOBAL *)(puVar14 + 99);
            FUN_140078b28(pHVar1,*(HGLOBAL *)(puVar14 + 0x7f),pvVar19,*(HGLOBAL *)(puVar14 + 0x69 ),
                          (longlong)puVar14);
            uVar4 = (uint)pvVar19;
          }
          if (((DAT_1400babf6 & 2) == 0) && ((*(uint *)(puVar14 + 0x11) & 2) != 0)) {
            *(uint *)(puVar14 + 0x11) = *(uint *)(puVar14 + 0x11) ^ 2;
          }
          GlobalUnlock(pvVar7);
          uVar4 = FUN_140073ce4(pHVar1,pvVar7,uVar4);
          if (uVar4 == 0) goto LAB_1400647e3;
          goto LAB_140063d96;
        }
      }
      if (local_d0 != (HGLOBAL)0x0) {
        GlobalFree(local_d0);
      }
      param_1 = local_b0;
      hMem = local_98;
      if (pvVar19 != (HGLOBAL)0x0) {
        GlobalFree(pvVar19);
        param_1 = local_b0;
        hMem = local_98;
      }
    }
    if (local_90 != (HGLOBAL)0x0) {
      GlobalFree(local_90);
    }
    if (local_a0 != (HGLOBAL)0x0) {
      GlobalFree(local_a0);
    }
    if (hMem != (HGLOBAL)0x0) {
      GlobalFree(hMem);
    }
  }
  if (pvVar7 != (HGLOBAL)0x0) {
    pvVar8 = GlobalLock(pvVar7);
    if (*(longlong *)((longlong)pvVar8 + 0x212) != 0) {
      hdc = GetDC(param_1);
      SelectPalette(hdc,*(HPALETTE *)((longlong)pvVar8 + 0x212),0);
      RealizePalette(hdc);
      param_1 = local_b0;
      ReleaseDC(local_b0,hdc);
    }
    if (*(HGDIOBJ *)((longlong)pvVar8 + 0x206) != (HGDIOBJ)0x0) {
      DeleteObject(*(HGDIOBJ *)((longlong)pvVar8 + 0x206));
      SendMessageA((HWND)0xffff,0x311,(WPARAM)DAT_140099270,0);
    }
    if (*(HDC *)((longlong)pvVar8 + 0x21e) != (HDC)0x0) {
      DeleteDC(*(HDC *)((longlong)pvVar8 + 0x21e));
    }
    GlobalUnlock(pvVar7);
    GlobalFree(pvVar7);
  }
  SetWindowLongPtrA(param_1,8,0);
  PostMessageA(DAT_140099270,6,1,0);
LAB_1400647e3:
  FUN_14008d510(local_48 ^ (ulonglong)auStackY_128);
  return;
}

```


Which seems quite a long function related to some rendering bullshit.


We are then calling that function here:
```
LAB_140065293:
          uVar17 = FUN_140063ae8(pHVar9,uVar17,uVar1);

```

which is in:

```


void openfileastempandopenwindows(LPCSTR param_1,uint param_2,undefined8 *param_3)

{
  uint uVar1;
  bool bVar2;
  int iVar3;
  BOOL BVar4;
  undefined4 uVar5;
  undefined8 uVar6;
  char *pcVar7;
  HWND pHVar8;
  HWND pHVar9;
  HGLOBAL pvVar10;
  LPVOID pvVar11;
  HDC hDC;
  int iVar12;
  UINT UVar13;
  char *pcVar14;
  char *pcVar15;
  longlong lVar16;
  uint uVar17;
  ulonglong uVar18;
  uint uVar19;
  bool bVar20;
  undefined auStackY_6b8 [32];
  int local_658;
  HGLOBAL local_650;
  int local_648;
  uint local_644;
  undefined8 *local_640;
  int local_638;
  HWND local_630;
  char *local_628;
  char *local_620;
  HINSTANCE local_618;
  undefined8 local_610;
  undefined8 uStack_608;
  undefined4 local_600;
  undefined8 local_5f8;
  tagRECT local_5f0;
  tagRECT local_5e0;
  WINDOWPLACEMENT local_5d0;
  char local_598 [272];
  char local_488 [272];
  char local_378 [272];
  char local_268 [272];
  char local_158 [272];
  ulonglong local_48;

  local_48 = DAT_140098000 ^ (ulonglong)auStackY_6b8;
  pHVar9 = (HWND)0x0;
  uVar19 = 0;
  iVar12 = 0;
  local_648 = 0;
  local_644 = 0;
  bVar20 = false;
  local_630 = (HWND)0x0;
  local_650 = (HGLOBAL)0x0;
  bVar2 = false;
  *param_3 = 0;
  local_640 = param_3;
  if (param_2 == 0x5d) {
    iVar3 = FUN_14006864c(param_1);
    if (iVar3 == 2) {
      param_2 = 0x5c;
    }
  }
  if ((((param_2 == 0xffffffa5) || (param_2 == 0xfffffffe)) || (param_2 == 2)) ||
     (local_658 = 0, param_2 - 0x5a < 3)) {
    local_658 = 1;
  }
  if ((((param_2 == 0x5a) || (param_2 == 0x5c)) ||
      ((param_2 == 0x5d || ((param_2 == 0x5f || (param_2 == 0x60)))))) || (param_2 == 0x61)) {
    iVar12 = 1;
  }
  else {
    DAT_1400990d4 = 0;
  }
  if ((int)param_2 < 0) {
    iVar12 = 1;
  }
  uVar1 = -param_2;
  if (-1 < (int)param_2) {
    uVar1 = param_2;
  }
  local_638 = iVar12;
  if ((uVar1 != 0x61) && (uVar6 = FUN_14006315c(), (int)uVar6 != 0)) goto LAB_140065729;
  SetCursor(DAT_1400baa28);
  some_thing_global = 1;
  pHVar8 = pHVar9;
  if ((int)uVar1 < 0x5b) {
    if (((uVar1 == 0x5a) || (uVar1 == 4)) || ((uVar1 == 5 || (uVar1 == 6)))) goto LAB_140064f9c;
    iVar12 = uVar1 - 7;
LAB_140064ebe:
    if ((iVar12 == 0) || (iVar12 == 1)) goto LAB_140064f9c;
    pcVar14 = local_598;
    lVar16 = 0x106;
    do {
      if ((lVar16 == -0x7ffffef8) || (pcVar14[(longlong)param_1 - (longlong)local_598] == '\0'))
      break;
      *pcVar14 = pcVar14[(longlong)param_1 - (longlong)local_598];
      pcVar14 = pcVar14 + 1;
      lVar16 = lVar16 + -1;
    } while (lVar16 != 0);
    pcVar15 = pcVar14 + -1;
    if (lVar16 != 0) {
      pcVar15 = pcVar14;
    }
    *pcVar15 = '\0';
    _splitpath_s(local_598,local_158,0x106,local_488,0x106,local_378,0x106,local_268,0x106);
    lVar16 = 0x106;
    pcVar15 = local_598;
    do {
      if ((lVar16 == -0x7ffffef8) || (pcVar15[0x220] == '\0')) break;
      *pcVar15 = pcVar15[0x220];
      pcVar15 = pcVar15 + 1;
      lVar16 = lVar16 + -1;
    } while (lVar16 != 0);
    pcVar14 = local_268;
    pcVar7 = pcVar15 + -1;
    if (lVar16 != 0) {
      pcVar7 = pcVar15;
    }
    *pcVar7 = '\0';
LAB_140064fe4:
    uVar17 = 0;
    FUN_140021134(local_598,0x106,(longlong)pcVar14);
    uVar5 = 0x1000000;
    local_628 = "OPWDocumentClass";
    local_620 = local_598;
    local_618 = DAT_140099278;
    local_610 = 0x8000000080000000;
    uStack_608 = 0x8000000080000000;
    local_5f8 = 0;
    BVar4 = IsIconic(DAT_140099270);
    if (BVar4 != 0) {
      uVar5 = 0;
      local_5d0.length = 0x2c;
      local_5d0.flags = 0;
      local_5d0.showCmd = 2;
      GetWindowPlacement(DAT_140099270,&local_5d0);
      iVar12 = local_5d0.rcNormalPosition.right - local_5d0.rcNormalPosition.left;
      iVar3 = local_5d0.rcNormalPosition.bottom - local_5d0.rcNormalPosition.top;
      if (0x10 < iVar12) {
        iVar12 = iVar12 + -0x10;
      }
      uStack_608 = CONCAT44(iVar3,iVar12);
      if (0x10 < iVar3) {
        uStack_608 = CONCAT44(iVar3 + -0x10,iVar12);
      }
    }
    local_600 = uVar5;
    SetRect(&local_5f0,0,0,1000,1000);
    if (uVar1 == 0x61) {
LAB_1400650e4:
      pHVar9 = pHVar8;
      if (pHVar8 == (HWND)0x0) {
        pHVar9 = DAT_140099270;
      }
      pHVar9 = CreateWindowExA(0,"OPWChartClass",(LPCSTR)0x0,0x42300000,0,0,local_5f0.right,
                               local_5f0.bottom,pHVar9,(HMENU)0x0,DAT_140099278,(LPVOID)0x0);
      uVar17 = ~-(uint)(pHVar9 != (HWND)0x0) & 0x2714;
      if (pHVar9 == (HWND)0x0) goto LAB_14006522e;
      *local_640 = pHVar9;
      uVar17 = DAT_1400bab40;
      pvVar10 = local_650;
      if (uVar1 != 0x61) {
        if ((uVar1 - 0x5a < 9) && ((0x123U >> (uVar1 - 0x5a & 0x1f) & 1) != 0)) {
          iVar12 = 1;
        }
        else {
          iVar12 = 0;
        }
        uVar17 = maybecreatetemp(pHVar8,uVar19,iVar12,local_658,param_1,(uint *)&local_640);
        if (uVar17 != 0) {
          bVar2 = false;
          goto LAB_140065235;
        }
        uVar17 = (uint)local_640;
      }
      if ((int)uVar1 < 0x5b) {
        if ((((uVar1 == 0x5a) || (uVar1 == 2)) || (uVar1 == 4)) ||
           (((uVar1 == 5 || (uVar1 == 6)) || ((uVar1 == 7 || (uVar1 == 8)))))) {
showwindownochecksumhere:
          ShowWindow(pHVar8,0);
          bVar2 = true;
          bVar20 = true;
LAB_140065293:
          uVar17 = FUN_140063ae8(pHVar9,uVar17,uVar1);
          goto LAB_1400652a0;
        }
LAB_140065212:
        uVar17 = FUN_140063370(pHVar9,uVar17,uVar1);
        if (uVar17 != 0) goto LAB_14006522e;
      }
      else {
        if ((uVar1 == 0x5b) || (uVar1 == 0x5c)) goto showwindownochecksumhere;
        if (uVar1 != 0x5f) {
          if (uVar1 == 0x60) goto showwindownochecksumhere;
          if (uVar1 != 99) goto LAB_140065212;
          bVar2 = false;
          goto LAB_140065293;
        }
        ShowWindow(pHVar8,0);
        bVar2 = true;
        bVar20 = true;
        uVar17 = FUN_140063370(pHVar9,uVar17,0x5f);
LAB_1400652a0:
        if (uVar17 != 0) goto LAB_140065235;
      }
      bVar2 = bVar20;
      pvVar10 = (HGLOBAL)GetWindowLongPtrA(pHVar9,8);
      pvVar11 = GlobalLock(pvVar10);
      if ((*(uint *)((longlong)pvVar11 + 0x22) & 1) != 0) {
        *(uint *)((longlong)pvVar11 + 0x22) = *(uint *)((longlong)pvVar11 + 0x22) ^ 1;
      }
      iVar12 = DAT_1400bac64;
      if ((int)uVar1 < 0x5b) {
        if (((((uVar1 != 0x5a) && (uVar1 != 2)) && (uVar1 != 4)) && ((uVar1 != 5 && (uVar1 != 6)) ))
           && (uVar1 != 7)) {
          bVar20 = uVar1 == 8;
LAB_140065351:
          if (!bVar20) {
            uVar19 = *(uint *)((longlong)pvVar11 + 0xe);
            iVar12 = *(int *)((longlong)pvVar11 + 10);
            if (((uVar1 == 0x5b) || (uVar1 == 0x62)) && ((DAT_1400babf6 & 0x400) != 0)) {
              uVar19 = (uint)(DAT_1400bac64 < 0);
              iVar12 = DAT_1400bac64;
            }
            uVar18 = (ulonglong)*(uint *)((longlong)pvVar11 + 0x5a);
            uVar17 = FUN_14007ede0(pHVar9,*(undefined4 *)((longlong)pvVar11 + 0x56),
                                   *(uint *)((longlong)pvVar11 + 0x5a),iVar12,uVar19);
            if ((uVar1 == 0x62) || (uVar17 = FUN_140055e48(pHVar9,(longlong)pvVar11), uVar17 == 0))
            {
              if ((iVar12 != 0) && ((uVar19 & 1) == 0)) {
                hDC = GetDC(pHVar9);
                FUN_14007ec98(hDC,iVar12);
                ReleaseDC(pHVar9,hDC);
                local_648 = iVar12;
              }
              local_644 = uVar19 & 1;
              if (uVar17 == 0) {
                GetClientRect(pHVar9,&local_5e0);
                FUN_14007ee90(pHVar9,0,uVar18,*(int *)((longlong)pvVar11 + 2),local_5e0.right,0);
                FUN_14007ee90(pHVar9,1,uVar18,*(int *)((longlong)pvVar11 + 6),local_5e0.bottom,0) ;
                SendMessageA(pHVar9,0x114,(ulonglong)*(ushort *)((longlong)pvVar11 + 2) << 0x10 |  99
                             ,0);
                SendMessageA(pHVar9,0x115,(ulonglong)*(ushort *)((longlong)pvVar11 + 6) << 0x10 |  99
                             ,0);
              }
            }
            goto LAB_140065489;
          }
        }
LAB_1400654bb:
        if ((DAT_1400babf6 & 0x400) == 0) {
          iVar12 = 0;
        }
        else if (uVar1 - 0x5a < 2) {
          if ((DAT_1400bac64 < 500) && (DAT_1400bac64 != 0)) {
            uVar5 = 1;
          }
          else {
            uVar5 = 0;
          }
          *(undefined4 *)((longlong)pvVar11 + 0xe) = uVar5;
          *(int *)((longlong)pvVar11 + 10) = iVar12;
        }
        uVar17 = FUN_14007ede0(pHVar9,*(undefined4 *)((longlong)pvVar11 + 0x56),
                               *(undefined4 *)((longlong)pvVar11 + 0x5a),iVar12,0);
        local_648 = 0;
        if (1 < iVar12 + 1U) {
          local_648 = iVar12;
        }
      }
      else {
        if (((uVar1 == 0x5b) || (uVar1 == 0x5c)) || ((uVar1 == 0x5f || (uVar1 == 0x60))))
        goto LAB_1400654bb;
        if (uVar1 != 0x61) {
          bVar20 = uVar1 == 99;
          goto LAB_140065351;
        }
        uVar17 = FUN_14007ede0(pHVar9,*(undefined4 *)((longlong)pvVar11 + 0x56),
                               *(undefined4 *)((longlong)pvVar11 + 0x5a),0,0);
      }
LAB_140065489:
      GlobalUnlock(pvVar10);
      pHVar8 = local_630;
    }
    else {
      pHVar8 = (HWND)SendMessageA(DAT_1400992a8,0x220,0,(LPARAM)&local_628);
      local_630 = pHVar8;
      if (pHVar8 == (HWND)0x0) {
        uVar17 = 0x2712;
      }
      else {
        GetClientRect(pHVar8,&local_5f0);
      }
      pvVar10 = (HGLOBAL)0x0;
      pHVar9 = (HWND)0x0;
      if (uVar17 == 0) goto LAB_1400650e4;
    }
  }
  else {
    if (((uVar1 != 0x5b) && (uVar1 != 0x5f)) && (uVar1 != 0x60)) {
      iVar12 = uVar1 - 0x62;
      goto LAB_140064ebe;
    }
LAB_140064f9c:
    uVar17 = FUN_14007ea70(500,local_598);
    if (uVar17 == 0) {
      uVar19 = DAT_140099140 + 1;
      FUN_140068b2c(local_488,0x106,&DAT_1400901ec,(ulonglong)uVar19);
      pcVar14 = local_488;
      goto LAB_140064fe4;
    }
LAB_14006522e:
    bVar2 = false;
    pvVar10 = (HGLOBAL)0x0;
  }
LAB_140065235:
  if (uVar17 == 0) {
    if (((((uVar1 == 4) || (uVar1 == 5)) || (uVar1 == 6)) ||
        (((uVar1 == 7 || (uVar1 == 8)) || ((uVar1 == 0x5b || ((uVar1 == 0x60 || (uVar1 == 0x62)) ))))
        )) || (uVar1 == 99)) {
      DAT_140099140 = DAT_140099140 + 1;
    }
    if (uVar1 == 0x61) goto LAB_140065729;
    if (((((uVar1 - 0x5d & 0xfffffffc) != 0) || (uVar1 == 0x5e)) && (!bVar2)) &&
       ((uVar1 - 0x5a & 0xfffffffd) != 0)) {
      ShowWindow(pHVar8,5);
      ShowWindow(pHVar9,5);
    }
    if (local_648 != 0) {
      FUN_1400690ec(pHVar9,local_648,local_644);
    }
    FUN_14006909c(pHVar8);
    FUN_14005a940(pHVar8,1);
    iVar12 = 0;
    if (uVar1 == 0x5a) {
LAB_1400656a2:
      FUN_140025c0c(pHVar9,0,0,1,0,0);
      FUN_140026c90(pHVar9,0x459,0,0,1,0);
      pvVar11 = GlobalLock(pvVar10);
      if (*(HGLOBAL *)((longlong)pvVar11 + 0xfe) != (HGLOBAL)0x0) {
        FUN_140043d1c(*(HGLOBAL *)((longlong)pvVar11 + 0xfe),0,iVar12,1,0);
      }
    }
    else {
      if (uVar1 != 0x5b) {
        iVar12 = 0;
        if ((uVar1 != 0x5f) && (uVar1 != 0x60)) {
          if (uVar1 == 0x62) goto LAB_140065753;
          if (uVar1 != 99) goto LAB_140065713;
          iVar12 = 1;
        }
        goto LAB_1400656a2;
      }
LAB_140065753:
      pvVar11 = GlobalLock(pvVar10);
      *(uint *)((longlong)pvVar11 + 0x22) = *(uint *)((longlong)pvVar11 + 0x22) | 0x80;
      FUN_140026c90(pHVar9,0x457,(uint)*(ushort *)((longlong)pvVar11 + 0xf6) << 0x10,0,1,0);
      FUN_140025c0c(pHVar9,0,0,1,0,0);
      if ((*(uint *)((longlong)pvVar11 + 0x22) & 0x80) != 0) {
        *(uint *)((longlong)pvVar11 + 0x22) = *(uint *)((longlong)pvVar11 + 0x22) ^ 0x80;
      }
      iVar12 = GetScrollPos(pHVar9,0);
      *(int *)((longlong)pvVar11 + 2) = iVar12;
      iVar12 = GetScrollPos(pHVar9,1);
      *(int *)((longlong)pvVar11 + 6) = iVar12;
    }
    GlobalUnlock(pvVar10);
  }
  else {
    if (pHVar8 == (HWND)0x0) {
      if (pHVar9 != (HWND)0x0) {
        DefWindowProcA(pHVar9,0x10,0,0);
      }
    }
    else {
      FUN_140067690(pHVar8);
      DefMDIChildProcA(pHVar8,0x10,0,0);
    }
    if (((uVar17 != 2) && (local_638 == 0)) && (uVar17 != 0xffffffff)) {
      UVar13 = 7;
      if (uVar17 == 7) {
        UVar13 = 0x5dd;
      }
      else if (uVar17 == 0x2716) {
        UVar13 = 0x33;
      }
      else if (uVar17 == 0x2717) {
        UVar13 = 0x3a;
      }
      else if (uVar17 == 0x2718) {
        UVar13 = (-(uint)(local_658 != 0) & 0x54c) + 0x98;
      }
      FUN_14005738c(UVar13);
    }
  }
LAB_140065713:
  SetCursor(DAT_1400baa20);
  some_thing_global = 0;
LAB_140065729:
  FUN_14008d510(local_48 ^ (ulonglong)auStackY_6b8);
  return;
}

```

Which is in our openfileastempandopenwindows function?????????? That seems kinda sus.

and here is the bullshit where we call that:

```

int load_file(LPCSTR filename,uint some_integer)

{
  int *piVar1;
  int iVar2;
  uint uVar3;
  HWND pHVar4;
  HGLOBAL hMem;
  LPVOID pvVar5;
  int iVar6;
  ulonglong uVar7;
  int iVar8;
  HWND window_thing_object [2];

  iVar2 = 0;
  SetCursor(DAT_1400baa28);
  iVar8 = 1;
  some_thing_global = 1;
  pHVar4 = FUN_1400657f0(filename);
  if (pHVar4 == (HWND)0x0) {
    if (some_integer == 0x5d) {
      some_integer = 0xfffffffd;
      iVar6 = iVar8;
    }
    else {
      iVar6 = 0;
      if (some_integer == 0x5c) {
        some_integer = 0xfffffffe;
        iVar6 = iVar8;
      }
    }
    iVar2 = openfileastempandopenwindows(filename,some_integer,window_thing_object);
    if (window_thing_object[0] == (HWND)0x0) {
      iVar2 = iVar8;
    }
    if (iVar2 != 0) goto LAB_140065c1c;
    if (((some_integer == 0xfffffffe) || (some_integer == 2)) || (some_integer - 0x5b < 2)) {
      uVar7 = (ulonglong)some_integer;
      pHVar4 = window_thing_object[0];
      do {
        checkvaliddatathing(pHVar4,filename,(int)uVar7);
      } while( true );
    }
    if (((iVar6 != 0) && (window_thing_object[0] != (HWND)0x0)) &&
       (hMem = (HGLOBAL)GetWindowLongPtrA(window_thing_object[0],8), hMem != (HGLOBAL)0x0)) {
      pvVar5 = GlobalLock(hMem);
      piVar1 = *(int **)((longlong)pvVar5 + 0x2ca);
      if (((piVar1 != (int *)0x0) && (*piVar1 != 0)) && (*(longlong *)(piVar1 + 3) != 0)) {
        *(undefined4 *)(*(longlong *)(piVar1 + 3) + 0x60) = 2;
      }
      GlobalUnlock(hMem);
    }
  }
  else {
    BringWindowToTop(pHVar4);
  }
  if (DAT_1400991b0 != (HWND)0x0) {
    uVar3 = FUN_140065a10(DAT_1400991b0);
    if (uVar3 == 0) {
      pHVar4 = GetParent(DAT_1400991b0);
      SendMessageA(pHVar4,0x10,0,0);
    }
    DAT_1400991b0 = (HWND)0x0;
  }

```


Wait fuck nevermind. That was the wrong call stack....

Here is the actual thing:

```


Säikeen tunnist Osoite           Paluun kohde     Paluun lähde     Kok Muistialue   Kommentti
29456 - Pääsäie
                00000087C2EFEFE8 00007FFBB4FA4F78 00007FFBDEF744D0 40  Järjestelmä  kernel32.CreateThread
                00000087C2EFF028 00007FFBB4F909B4 00007FFBB4FA4F78 90  Järjestelmä  winspool.Ordinal#361+B8
                00000087C2EFF0B8 00007FFBDD363324 00007FFBB4F909B4 70  Järjestelmä  winspool.DocumentEvent+44
                00000087C2EFF128 00007FFBDD2FEF45 00007FFBDD363324 350 Järjestelmä  gdi32full.DocumentEventEx+114
                00000087C2EFF478 00007FFBDD324717 00007FFBDD2FEF45 80  Järjestelmä  gdi32full.hdcCreateDCW+195
                00000087C2EFF4F8 00007FFBDD323B21 00007FFBDD324717 40  Järjestelmä  gdi32full.SetBitmapDimensionEx+147
                00000087C2EFF538 00007FF79ACCDBD8 00007FFBDD323B21 310 Käyttäjäalue gdi32full.CreateICA+11
                00000087C2EFF848 00007FF79AC9F587 00007FF79ACCDBD8 50  Käyttäjäalue orgchart.00007FF79ACCDBD8
                00000087C2EFF898 00007FF79AC9EF70 00007FF79AC9F587 1F0 Käyttäjäalue orgchart.00007FF79AC9F587
                00000087C2EFFA88 00007FF79AC9E650 00007FF79AC9EF70 90  Käyttäjäalue orgchart.00007FF79AC9EF70
                00000087C2EFFB18 00007FF79ACB592E 00007FF79AC9E650 40  Käyttäjäalue orgchart.00007FF79AC9E650
                00000087C2EFFB58 00007FF79ACB5B81 00007FF79ACB592E 40  Käyttäjäalue orgchart.00007FF79ACB592E
                00000087C2EFFB98 00007FF79ACB5C9F 00007FF79ACB5B81 150 Käyttäjäalue orgchart.00007FF79ACB5B81
                00000087C2EFFCE8 00007FF79ACA8D0C 00007FF79ACB5C9F 1D0 Käyttäjäalue orgchart.00007FF79ACB5C9F
                00000087C2EFFEB8 00007FF79ACDD472 00007FF79ACA8D0C 40  Käyttäjäalue orgchart.00007FF79ACA8D0C
                00000087C2EFFEF8 00007FFBDEF7259D 00007FF79ACDD472 30  Järjestelmä  orgchart.00007FF79ACDD472
                00000087C2EFFF28 00007FFBDFFCAF38 00007FFBDEF7259D 80  Järjestelmä  kernel32.BaseThreadInitThunk+1D
                00000087C2EFFFA8 0000000000000000 00007FFBDFFCAF38     Käyttäjäalue ntdll.RtlUserThreadStart+28
10956
                00000087C2FFFA78 00007FFBDFFA586E 00007FFBE0013FF4 2E0 Järjestelmä  ntdll.NtWaitForWorkViaWorkerFactory+14
                00000087C2FFFD58 00007FFBDEF7259D 00007FFBDFFA586E 30  Järjestelmä  ntdll.RtlClearThreadWorkOnBehalfTicket+35E
                00000087C2FFFD88 00007FFBDFFCAF38 00007FFBDEF7259D 80  Järjestelmä  kernel32.BaseThreadInitThunk+1D
                00000087C2FFFE08 0000000000000000 00007FFBDFFCAF38     Käyttäjäalue ntdll.RtlUserThreadStart+28
21288
                00000087C30FFBF8 00007FFBDFFA586E 00007FFBE0013FF4 2E0 Järjestelmä  ntdll.NtWaitForWorkViaWorkerFactory+14
                00000087C30FFED8 00007FFBDEF7259D 00007FFBDFFA586E 30  Järjestelmä  ntdll.RtlClearThreadWorkOnBehalfTicket+35E
                00000087C30FFF08 00007FFBDFFCAF38 00007FFBDEF7259D 80  Järjestelmä  kernel32.BaseThreadInitThunk+1D
                00000087C30FFF88 0000000000000000 00007FFBDFFCAF38     Käyttäjäalue ntdll.RtlUserThreadStart+28
25044
                00000087C32FF338 00007FFBDD7B6849 00007FFBE0010EF4 2E0 Järjestelmä  ntdll.NtWaitForMultipleObjects+14
                00000087C32FF618 00007FFBDE0807AD 00007FFBDD7B6849 2A0 Järjestelmä  kernelbase.WaitForMultipleObjectsEx+E9
                00000087C32FF8B8 00007FFBDE08061A 00007FFBDE0807AD 50  Järjestelmä  combase.CoFreeUnusedLibrariesEx+82D
                00000087C32FF908 00007FFBDE08040F 00007FFBDE08061A 80  Järjestelmä  combase.CoFreeUnusedLibrariesEx+69A
                00000087C32FF988 00007FFBDE080829 00007FFBDE08040F 30  Järjestelmä  combase.CoFreeUnusedLibrariesEx+48F
                00000087C32FF9B8 00007FFBDEF7259D 00007FFBDE080829 30  Järjestelmä  combase.CoFreeUnusedLibrariesEx+8A9
                00000087C32FF9E8 00007FFBDFFCAF38 00007FFBDEF7259D 80  Järjestelmä  kernel32.BaseThreadInitThunk+1D
                00000087C32FFA68 0000000000000000 00007FFBDFFCAF38     Käyttäjäalue ntdll.RtlUserThreadStart+28
10576
                00000087C31FFB48 00007FFBDFFA586E 00007FFBE0013FF4 2E0 Järjestelmä  ntdll.NtWaitForWorkViaWorkerFactory+14
                00000087C31FFE28 00007FFBDEF7259D 00007FFBDFFA586E 30  Järjestelmä  ntdll.RtlClearThreadWorkOnBehalfTicket+35E
                00000087C31FFE58 00007FFBDFFCAF38 00007FFBDEF7259D 80  Järjestelmä  kernel32.BaseThreadInitThunk+1D
                00000087C31FFED8 0000000000000000 00007FFBDFFCAF38     Käyttäjäalue ntdll.RtlUserThreadStart+28
14816
                00000087C33FF638 00007FFBDFFA586E 00007FFBE0013FF4 2E0 Järjestelmä  ntdll.NtWaitForWorkViaWorkerFactory+14
                00000087C33FF918 00007FFBDEF7259D 00007FFBDFFA586E 30  Järjestelmä  ntdll.RtlClearThreadWorkOnBehalfTicket+35E
                00000087C33FF948 00007FFBDFFCAF38 00007FFBDEF7259D 80  Järjestelmä  kernel32.BaseThreadInitThunk+1D
                00000087C33FF9C8 0000000000000000 00007FFBDFFCAF38     Käyttäjäalue ntdll.RtlUserThreadStart+28
28332
                00000087C34FF828 00007FFBDFFA586E 00007FFBE0013FF4 2E0 Järjestelmä  ntdll.NtWaitForWorkViaWorkerFactory+14
                00000087C34FFB08 00007FFBDEF7259D 00007FFBDFFA586E 30  Järjestelmä  ntdll.RtlClearThreadWorkOnBehalfTicket+35E
                00000087C34FFB38 00007FFBDFFCAF38 00007FFBDEF7259D 80  Järjestelmä  kernel32.BaseThreadInitThunk+1D
                00000087C34FFBB8 0000000000000000 00007FFBDFFCAF38     Käyttäjäalue ntdll.RtlUserThreadStart+28


```


Here is the place where we are:

```

void maybe_load_data(HWND window_handle,longlong window_lock,HANDLE filehandle)

{
  bool bVar1;
  bool bVar2;
  uint uVar3;
  uint uVar4;
  undefined8 uVar5;
  ulonglong uVar6;
  int iVar7;
  undefined auStack_1e8 [32];
  uint local_1c8;
  uint local_1c4;
  uint local_1c0;
  uint local_1bc;
  HWND local_1b8;
  undefined local_1a8 [112];
  undefined4 local_138;
  undefined4 local_134;
  undefined4 local_130;
  int local_12c;
  undefined8 local_128;
  undefined8 uStack_120;
  undefined4 local_114;
  undefined4 local_f8;
  undefined8 local_78;
  undefined8 uStack_70;
  undefined4 local_68;
  ulonglong local_48;

  local_48 = DAT_140098000 ^ (ulonglong)auStack_1e8;
  local_1c4 = 0;
  bVar1 = false;
  local_1b8 = window_handle;
LAB_14004eecd:
  uVar4 = FUN_14005333c(filehandle,&local_1c4,&local_1c0);
  uVar3 = local_1c4;
  if (uVar4 != 0) goto LAB_14004f3e1;
  iVar7 = 0;
  if (local_1c4 < 0x96) {
    if (local_1c4 == 0x95) {
      FUN_140054444((longlong)local_1a8,0x1400a97b0);
      *(undefined8 *)(window_lock + 0x3d8) = local_78;
      *(undefined8 *)(window_lock + 0x3e0) = uStack_70;
      *(undefined4 *)(window_lock + 1000) = local_68;
      *(int *)(window_lock + 0x292) = local_12c + -0x5dc;
      *(undefined4 *)(window_lock + 0x296) = local_138;
      *(undefined4 *)(window_lock + 0x29a) = local_134;
      *(undefined4 *)(window_lock + 0x29e) = local_130;
      *(undefined4 *)(window_lock + 0x28e) = local_114;
      *(undefined4 *)(window_lock + 0x2be) = local_f8;
      *(undefined8 *)(window_lock + 0x2a6) = local_128;
      *(undefined8 *)(window_lock + 0x2ae) = uStack_120;
      goto LAB_14004f3b8;
    }
    if (0x54 < local_1c4) {
      if (local_1c4 == 0x56) {
        FUN_140054854(0x1400bb580,&DAT_1400980ac,&DAT_140099028);
      }
      else {
        if (local_1c4 == 0x90) {
          uVar5 = FUN_14004ed08(window_lock);
          uVar4 = (uint)uVar5;
          goto joined_r0x00014004ef74;
        }
        if (local_1c4 == 0x91) {
          if (!bVar1) goto LAB_14004f3e1;
          _DAT_140099044 = ((uint)(ushort)DAT_1400a97b2 * 0x90) / DAT_1400980b8;
          _DAT_140099040 = ((uint)DAT_1400a97b2._2_2_ * 0x90) / DAT_1400980b8;
        }
        else if (local_1c4 == 0x92) {
          _DAT_1400bb550 =
               CONCAT26((ushort)DAT_1400a97b6,
                        CONCAT24(DAT_1400a97b2._2_2_,CONCAT22((ushort)DAT_1400a97b2,DAT_1400a97b0 )))
          ;
          uRam00000001400bb558 =
               CONCAT26(DAT_1400a97be,CONCAT42(_DAT_1400a97ba,DAT_1400a97b6._2_2_));
        }
        else if (local_1c4 == 0x93) {
          FUN_14005439c(&DAT_1400bb500,0x1400a97b0);
        }
      }
      goto LAB_14004f3b8;
    }
    if (local_1c4 == 0x54) {
      DAT_1400bb560 =
           CONCAT26((ushort)DAT_1400a97b6,
                    CONCAT24(DAT_1400a97b2._2_2_,CONCAT22((ushort)DAT_1400a97b2,DAT_1400a97b0))) ;
      DAT_1400bb568 = CONCAT26(DAT_1400a97be,CONCAT42(_DAT_1400a97ba,DAT_1400a97b6._2_2_));
      DAT_1400bb570 = _DAT_1400a97c0;
      goto LAB_14004f3b8;
    }
    if (local_1c4 == 0x20) {
      if (!bVar1) goto LAB_14004f3e1;
      if (DAT_1400a97be == 1) {
        if (DAT_1400a97c3 == '\x01') {
          uVar4 = DAT_1400983fc | 0xff000000;
        }
        else {
          uVar4 = (_DAT_1400a97c0 >> 0x10 & 0xff) << 8 | (_DAT_1400a97c0 >> 8 & 0xff) << 0x10 |
                  _DAT_1400a97c0 & 0xff;
        }
        *(uint *)(window_lock + 0xfa) = uVar4;
        uVar4 = DAT_1400980b8;
        *(uint *)(window_lock + 0x1f6) = (uint)(DAT_1400a97c4 * 0x90) / DAT_1400980b8;
        *(uint *)(window_lock + 0xa6) = (uint)(DAT_1400a97c8 * 0x90) / uVar4;
        *(uint *)(window_lock + 0xaa) = (uint)(DAT_1400a97cc * 0x90) / uVar4;
      }
      else {
        iVar7 = 0x5e4;
      }
      if (iVar7 != 0) goto LAB_14004f3e1;
      uVar4 = 0;
    }
    else {
      if (local_1c4 != 0x21) {
        if (local_1c4 != 0x22) {
          if (local_1c4 == 0x24) {
            *(int *)(window_lock + 0xf6) = (int)DAT_1400a97b0;
          }
          else if (local_1c4 == 0x53) {
            _DAT_1400bb540 =
                 CONCAT26((ushort)DAT_1400a97b6,
                          CONCAT24(DAT_1400a97b2._2_2_,CONCAT22((ushort)DAT_1400a97b2,DAT_1400a97 b0)
                                  ));
            uRam00000001400bb548 =
                 CONCAT26(DAT_1400a97be,CONCAT42(_DAT_1400a97ba,DAT_1400a97b6._2_2_));
          }
          goto LAB_14004f3b8;
        }
        if (bVar1) {
          uVar5 = somebullshitfunctioncreatesthread(window_lock,local_1c0);
          uVar4 = (uint)uVar5;
          goto joined_r0x00014004ef74;
        }
        goto LAB_14004f3e1;
      }
      DAT_1400980b8 = ((uint)DAT_1400a97b2._2_2_ * (uint)(ushort)DAT_1400a97b6) / 100;
      uVar4 = ~-(uint)(DAT_1400980b8 != 0) & 0x5dd;
      if (DAT_1400980b8 == 0) goto LAB_14004f3e1;
      bVar1 = true;
    }
  }
  else if (local_1c4 < 0x400b) {
    if (local_1c4 == 0x400a) {
      local_1c8 = 0;
      bVar2 = false;
      do {
        uVar4 = FUN_14005333c(filehandle,&local_1c8,&local_1bc);
        if (uVar4 != 0) break;
        if (local_1c8 == 0x23) {
          uVar4 = FUN_140053550(window_lock,(ulonglong)local_1bc);
          if (uVar4 != 0) goto LAB_14004f343;
          bVar2 = true;
        }
      } while (local_1c8 != 0x600a);
      if (!bVar2) {
        uVar4 = 0x5dd;
      }
LAB_14004f343:
      if (uVar4 == 0) {
        uVar4 = 0;
        goto joined_r0x00014004ef74;
      }
      goto LAB_14004f3e1;
    }
    if (local_1c4 == 0x96) {
      FUN_140054300((longlong)local_1a8,0x1400a97b0);
      *(undefined8 *)(window_lock + 0x3d8) = local_78;
      *(undefined8 *)(window_lock + 0x3e0) = uStack_70;
      *(undefined4 *)(window_lock + 1000) = local_68;
      goto LAB_14004f3b8;
    }
    if (local_1c4 == 0x98) {
      if ((ushort)DAT_1400a97b2 == 0) {
        *(uint *)(window_lock + 0x22) = *(uint *)(window_lock + 0x22) | 0x800;
      }
      else if ((*(uint *)(window_lock + 0x22) & 0x800) != 0) {
        *(uint *)(window_lock + 0x22) = *(uint *)(window_lock + 0x22) ^ 0x800;
      }
      goto LAB_14004f3b8;
    }
    if (local_1c4 == 0x9b) {
      if (local_1c0 < 10) {
        iVar7 = 0x6a;
      }
      else {
        if ((ushort)DAT_1400a97b2 == 0) {
          if ((*(uint *)(window_lock + 0x2a) & 4) != 0) {
            *(uint *)(window_lock + 0x2a) = *(uint *)(window_lock + 0x2a) ^ 4;
          }
        }
        else {
          *(uint *)(window_lock + 0x2a) = *(uint *)(window_lock + 0x2a) | 4;
        }
        *(uint *)(window_lock + 0x3a) = (uint)(ushort)DAT_1400a97b6;
        *(uint *)(window_lock + 0x2a2) = (uint)DAT_1400a97b6._2_2_;
        *(uint *)(window_lock + 0x226) = (uint)DAT_1400a97b2._2_2_;
      }
      if (iVar7 == 0) {
        uVar4 = 0;
        goto joined_r0x00014004ef74;
      }
      goto LAB_14004f3e1;
    }
    if (local_1c4 == 0x4006) {
      uVar6 = FUN_14004f940(window_lock,filehandle);
      uVar4 = (uint)uVar6;
    }
    else {
      if (local_1c4 != 0x4009) goto LAB_14004f3b8;
      uVar6 = FUN_1400502bc(window_lock,filehandle);
      uVar4 = (uint)uVar6;
    }
  }
  else if (local_1c4 == 0x400b) {
    uVar4 = FUN_14004f5d0(window_lock,filehandle);
    if (uVar4 != 0) goto LAB_14004f3e1;
  }
  else if (local_1c4 == 0x400e) {
    uVar4 = FUN_1400521dc(local_1b8,window_lock,filehandle);
  }
  else if (local_1c4 == 0x4010) {
    uVar5 = FUN_14004f79c(window_lock,filehandle);
    uVar4 = (uint)uVar5;
  }
  else {
    if (local_1c4 != 0x4012) goto LAB_14004f3b8;
    uVar4 = FUN_140051b6c(local_1b8,window_lock,filehandle);
  }
joined_r0x00014004ef74:
  if (uVar4 != 0) goto LAB_14004f3e1;
LAB_14004f3b8:
  if (uVar3 == 0x6003) {
LAB_14004f3e1:
    FUN_14008d510(local_48 ^ (ulonglong)auStack_1e8);
    return;
  }
  goto LAB_14004eecd;
}


```

Here is the call table on the second thread creation call:

```

Säikeen tunnist Osoite           Paluun kohde     Paluun lähde     Kok Muistialue   Kommentti
20416 - Pääsäie
                0000004772AFECA8 00007FFBB4FA4F78 00007FFBDEF744D0 40  Järjestelmä  kernel32.CreateThread
                0000004772AFECE8 00007FFBB4F909B4 00007FFBB4FA4F78 90  Järjestelmä  winspool.Ordinal#361+B8
                0000004772AFED78 00007FFBDD363324 00007FFBB4F909B4 70  Järjestelmä  winspool.DocumentEvent+44
                0000004772AFEDE8 00007FFBDD2FEF45 00007FFBDD363324 350 Järjestelmä  gdi32full.DocumentEventEx+114
                0000004772AFF138 00007FFBDD324717 00007FFBDD2FEF45 80  Järjestelmä  gdi32full.hdcCreateDCW+195
                0000004772AFF1B8 00007FFBDD323B21 00007FFBDD324717 40  Järjestelmä  gdi32full.SetBitmapDimensionEx+147
                0000004772AFF1F8 00007FF79ACCE195 00007FFBDD323B21 30  Käyttäjäalue gdi32full.CreateICA+11
                0000004772AFF228 00007FF79ACCE092 00007FF79ACCE195 310 Käyttäjäalue orgchart.00007FF79ACCE195
                0000004772AFF538 00007FF79AC9F587 00007FF79ACCE092 50  Käyttäjäalue orgchart.00007FF79ACCE092
                0000004772AFF588 00007FF79AC9EF70 00007FF79AC9F587 1F0 Käyttäjäalue orgchart.00007FF79AC9F587
                0000004772AFF778 00007FF79AC9E650 00007FF79AC9EF70 90  Käyttäjäalue orgchart.00007FF79AC9EF70
                0000004772AFF808 00007FF79ACB592E 00007FF79AC9E650 40  Käyttäjäalue orgchart.00007FF79AC9E650
                0000004772AFF848 00007FF79ACB5B81 00007FF79ACB592E 40  Käyttäjäalue orgchart.00007FF79ACB592E
                0000004772AFF888 00007FF79ACB5C9F 00007FF79ACB5B81 150 Käyttäjäalue orgchart.00007FF79ACB5B81
                0000004772AFF9D8 00007FF79ACA8D0C 00007FF79ACB5C9F 1D0 Käyttäjäalue orgchart.00007FF79ACB5C9F
                0000004772AFFBA8 00007FF79ACDD472 00007FF79ACA8D0C 40  Käyttäjäalue orgchart.00007FF79ACA8D0C
                0000004772AFFBE8 00007FFBDEF7259D 00007FF79ACDD472 30  Järjestelmä  orgchart.00007FF79ACDD472
                0000004772AFFC18 00007FFBDFFCAF38 00007FFBDEF7259D 80  Järjestelmä  kernel32.BaseThreadInitThunk+1D
                0000004772AFFC98 0000000000000000 00007FFBDFFCAF38     Käyttäjäalue ntdll.RtlUserThreadStart+28
24472
                0000004772FFFC48 00007FFBDFFA586E 00007FFBE0013FF4 2E0 Järjestelmä  ntdll.NtWaitForWorkViaWorkerFactory+14
                0000004772FFFF28 00007FFBDEF7259D 00007FFBDFFA586E 30  Järjestelmä  ntdll.RtlClearThreadWorkOnBehalfTicket+35E
                0000004772FFFF58 00007FFBDFFCAF38 00007FFBDEF7259D 80  Järjestelmä  kernel32.BaseThreadInitThunk+1D
                0000004772FFFFD8 0000000000000000 00007FFBDFFCAF38     Käyttäjäalue ntdll.RtlUserThreadStart+28
24244
                0000004772BFF498 00007FFBDFFA586E 00007FFBE0013FF4 2E0 Järjestelmä  ntdll.NtWaitForWorkViaWorkerFactory+14
                0000004772BFF778 00007FFBDEF7259D 00007FFBDFFA586E 30  Järjestelmä  ntdll.RtlClearThreadWorkOnBehalfTicket+35E
                0000004772BFF7A8 00007FFBDFFCAF38 00007FFBDEF7259D 80  Järjestelmä  kernel32.BaseThreadInitThunk+1D
                0000004772BFF828 0000000000000000 00007FFBDFFCAF38     Käyttäjäalue ntdll.RtlUserThreadStart+28
27540
                0000004772CFFAA8 00007FFBDFFA586E 00007FFBE0013FF4 2E0 Järjestelmä  ntdll.NtWaitForWorkViaWorkerFactory+14
                0000004772CFFD88 00007FFBDEF7259D 00007FFBDFFA586E 30  Järjestelmä  ntdll.RtlClearThreadWorkOnBehalfTicket+35E
                0000004772CFFDB8 00007FFBDFFCAF38 00007FFBDEF7259D 80  Järjestelmä  kernel32.BaseThreadInitThunk+1D
                0000004772CFFE38 0000000000000000 00007FFBDFFCAF38     Käyttäjäalue ntdll.RtlUserThreadStart+28
23456
                00000047730FF528 00007FFBDFFA586E 00007FFBE0013FF4 2E0 Järjestelmä  ntdll.NtWaitForWorkViaWorkerFactory+14
                00000047730FF808 00007FFBDEF7259D 00007FFBDFFA586E 30  Järjestelmä  ntdll.RtlClearThreadWorkOnBehalfTicket+35E
                00000047730FF838 00007FFBDFFCAF38 00007FFBDEF7259D 80  Järjestelmä  kernel32.BaseThreadInitThunk+1D
                00000047730FF8B8 0000000000000000 00007FFBDFFCAF38     Käyttäjäalue ntdll.RtlUserThreadStart+28
8444
                0000004772DFF748 00007FFBDFFA586E 00007FFBE0013FF4 2E0 Järjestelmä  ntdll.NtWaitForWorkViaWorkerFactory+14
                0000004772DFFA28 00007FFBDEF7259D 00007FFBDFFA586E 30  Järjestelmä  ntdll.RtlClearThreadWorkOnBehalfTicket+35E
                0000004772DFFA58 00007FFBDFFCAF38 00007FFBDEF7259D 80  Järjestelmä  kernel32.BaseThreadInitThunk+1D
                0000004772DFFAD8 0000000000000000 00007FFBDFFCAF38     Käyttäjäalue ntdll.RtlUserThreadStart+28
27064
                0000004772EFF888 00007FFBDD7B6849 00007FFBE0010EF4 2E0 Järjestelmä  ntdll.NtWaitForMultipleObjects+14
                0000004772EFFB68 00007FFBDE0807AD 00007FFBDD7B6849 2A0 Järjestelmä  kernelbase.WaitForMultipleObjectsEx+E9
                0000004772EFFE08 00007FFBDE08061A 00007FFBDE0807AD 50  Järjestelmä  combase.CoFreeUnusedLibrariesEx+82D
                0000004772EFFE58 00007FFBDE08040F 00007FFBDE08061A 80  Järjestelmä  combase.CoFreeUnusedLibrariesEx+69A
                0000004772EFFED8 00007FFBDE080829 00007FFBDE08040F 30  Järjestelmä  combase.CoFreeUnusedLibrariesEx+48F
                0000004772EFFF08 00007FFBDEF7259D 00007FFBDE080829 30  Järjestelmä  combase.CoFreeUnusedLibrariesEx+8A9
                0000004772EFFF38 00007FFBDFFCAF38 00007FFBDEF7259D 80  Järjestelmä  kernel32.BaseThreadInitThunk+1D
                0000004772EFFFB8 0000000000000000 00007FFBDFFCAF38     Käyttäjäalue ntdll.RtlUserThreadStart+28


```




Here is the functionality which we want to patch out:

```

       14004e63d 45  85  ff       TEST       show_data_maybe ,show_data_maybe
       14004e640 74  10           JZ         LAB_14004e652
       14004e642 4d  8b  c5       MOV        param_3 ,opened_file
       14004e645 48  8b  d7       MOV        maybe_buffer ,somecheckvar
       14004e648 48  8b  cd       MOV        window_handle ,RBP
       14004e64b e8  34  08       CALL       maybe_load_data                                  undefined maybe_load_data(HWND w
                 00  00
       14004e650 8b  d8           MOV        EBX ,window_lock


```

Now I don't think that the program will work if we patch out the call to maybe_load_data, because some shit depends on it further down the line, but let's see..

e8  34  08 00  00

Ok, so if we nop out those instructions, we just get an error message when opening the file thing. Instead, let's just put a mov ebx, 1 there and see what happens...


```

       14004e64b bb  00  00       MOV        EBX ,0x0
                 00  00

```

Here is the actual bullshit function:

```


undefined8 somebullshitfunctioncreatesthread(longlong param_1,uint param_2)

{
  uint uVar1;
  LPVOID pvVar2;
  longlong driverbullshit;
  undefined2 uVar3;
  int local_res10 [2];
  undefined8 in_stack_ffffffffffffffe8;

  if (param_2 < 0x2c) {
    return 0x6a;
  }
  if ((short)DAT_1400a97b2 != 0) {
    return 0x5e8;
  }
  pvVar2 = GlobalLock(*(HGLOBAL *)(param_1 + 0xae));
  if (DAT_1400a97b2._2_2_ == 0) {
    uVar3 = 1;
  }
  else {
    uVar3 = 2;
  }
  *(undefined2 *)((longlong)pvVar2 + 0x2c) = uVar3;
  *(undefined2 *)((longlong)pvVar2 + 0x2e) = DAT_1400a97d0;
  uVar1 = *(uint *)(param_1 + 0x22);
  if (DAT_1400a97b6._2_2_ == 0) {
    if ((uVar1 & 4) != 0) {
      uVar1 = uVar1 ^ 4;
      goto LAB_14004f493;
    }
  }
  else {
    uVar1 = uVar1 | 4;
LAB_14004f493:
    *(uint *)(param_1 + 0x22) = uVar1;
  }
  if (_DAT_1400a97ba == 0) {
    if ((uVar1 & 2) != 0) {
      uVar1 = uVar1 ^ 2;
      goto LAB_14004f4ac;
    }
  }
  else {
    uVar1 = uVar1 | 2;
LAB_14004f4ac:
    *(uint *)(param_1 + 0x22) = uVar1;
  }
  uVar1 = DAT_1400980b8;
  *(uint *)(param_1 + 0x7a) = (uint)(_DAT_1400a97bc * 0x90) / DAT_1400980b8;
  *(uint *)(param_1 + 0x82) = (uint)(_DAT_1400a97c0 * 0x90) / uVar1;
  *(uint *)(param_1 + 0x7e) = (uint)(DAT_1400a97c4 * 0x90) / uVar1;
  *(uint *)(param_1 + 0x86) = (uint)(DAT_1400a97c8 * 0x90) / uVar1;
  *(uint *)(param_1 + 0xa2) = (uint)(DAT_1400a97cc * 0x90) / uVar1;
  *(uint *)(param_1 + 0x6e) = (uint)(DAT_1400a97d4 * 0x90) / uVar1;
  *(uint *)(param_1 + 0x72) = (uint)(DAT_1400a97d8 * 0x90) / uVar1;
  GlobalUnlock(*(HGLOBAL *)(param_1 + 0xae));
  *(LPCSTR)(param_1 + 0x2d2) = '\0';
  local_res10[0] = 1;
  driverbullshit =
       createdrivericathing
                 ((LPCSTR)(param_1 + 0x2d2),*(HGLOBAL *)(param_1 + 0xae),(int *)(param_1 + 0x8a),
                  (int *)(param_1 + 0x66),0,local_res10,in_stack_ffffffffffffffe8,0);
  uVar1 = *(uint *)(param_1 + 0x22);
  if (local_res10[0] == 0) {
    if ((uVar1 & 0x2000) == 0) goto LAB_14004f5a5;
    uVar1 = uVar1 ^ 0x2000;
  }
  else {
    uVar1 = uVar1 | 0x2000;
  }
  *(uint *)(param_1 + 0x22) = uVar1;
LAB_14004f5a5:
  if (driverbullshit != 0) {
    DeleteDC(*(HDC *)(param_1 + 0x21e));
    *(longlong *)(param_1 + 0x21e) = driverbullshit;
  }
  return 0;
}

```

Here:

```

  if (driverbullshit != 0) {
    DeleteDC(*(HDC *)(param_1 + 0x21e));
    *(longlong *)(param_1 + 0x21e) = driverbullshit;
  }

```

we check if the thing is not zero, so therefore if we just set zero there we should be good???

This probably fucks up something else later on, but maybe this will solve it???

Here is the call thing:

```

       14004f57b 40  88  31       MOV        byte ptr [param_1 ],SIL
       14004f57e 89  7c  24       MOV        dword ptr [RSP  + local_res10 ],EDI
                 58
       14004f582 e8  75  e4       CALL       createdrivericathing                             undefined createdrivericathing(L
                 02  00


```



C:\Users\elsku\winafl\winafl\build\bin\Release\afl-fuzz.exe -d -i c:\Users\elsku\inputs -o c:\Users\elsku\outputs -D C:\Users\elsku\dynamorio2\DynamoRIO-Windows-11.3.0-1\bin64 -I 40000   -t 40000 -f test.opx -- -coverage_module ORGCHART.EXE -fuzz_iterations 1000 -persistence_mode native -target_module ORGCHART.EXE -verbose 100 -target_offset 0x4E2DC -nargs 6 -call_convention fastcall -- "C:\Program Files\Microsoft Office\root\Office16\ORGCHART.EXE" "@@"


The fail fast bullshit is called from here:

```


int * FUN_1400224dc(HGLOBAL param_1,int param_2)

{
  bool bVar1;
  SIZE_T SVar2;
  int *piVar3;

  SVar2 = GlobalSize(param_1);
  if (((param_2 < 0) ||
      (piVar3 = (int *)((longlong)param_1 + (longlong)param_2 * 4 + 0xc4),
      (int *)((longlong)param_1 + SVar2) <= piVar3)) || (*piVar3 < 0)) {
    bVar1 = true;
  }
  else {
    bVar1 = false;
  }
  if (bVar1) {
    RaiseFailFastException((PEXCEPTION_RECORD)0x0,(PCONTEXT)0x0,0);
  }
  piVar3 = (int *)((longlong)*(int *)((longlong)param_1 + (longlong)param_2 * 4 + 0xc4) +
                  (longlong)param_1);
  if ((int *)((longlong)param_1 + SVar2) <= piVar3) {
    RaiseFailFastException((PEXCEPTION_RECORD)0x0,(PCONTEXT)0x0,0);
  }
  return piVar3;
}


```

here is the calling function again:

```


ulonglong FUN_14004f940(longlong window_lock_bullshit,HANDLE filehandle)

{
  bool bVar1;
  uint uVar2;
  longlong lVar3;
  int *piVar4;
  short *psVar5;
  short *psVar6;
  ulonglong uVar7;
  uint uVar8;
  short *psVar9;
  short *hMem;
  int iVar10;
  short *psVar11;
  int iVar12;
  short *psVar13;
  int iVar14;
  int iVar16;
  short *hMem_00;
  int local_res20;
  int local_68;
  uint local_64;
  int local_60;
  uint local_5c;
  short *local_58;
  short *local_50 [2];
  int iVar15;

  hMem = (short *)0x0;
  local_68 = 1;
  local_64 = 0;
  bVar1 = false;
  local_res20 = 0;
  local_50[0] = (short *)0x0;
  local_58 = (short *)0x0;
  psVar11 = hMem;
  psVar13 = hMem;
  hMem_00 = hMem;
  psVar5 = hMem;
  psVar6 = hMem;
  do {
    iVar12 = (int)psVar13;
    iVar10 = (int)psVar11;
    local_60 = iVar12;
    uVar2 = read_file_buffer(filehandle,&local_64,&local_5c);
    iVar16 = 0;
    iVar15 = 0;
    iVar14 = 0;
    if (uVar2 != 0) break;
    if (local_64 < 0x88) {
      if (local_64 == 0x87) {
        if ((hMem_00 == (short *)0x0) || (!bVar1)) {
          if ((hMem != (short *)0x0) &&
             ((0 < iVar12 && (psVar9 = psVar5, iVar10 = iVar12, iVar12 <= *(int *)(psVar5 + 0x46) )))
             ) goto LAB_14004fddd;
        }
        else if ((0 < iVar10) && (psVar9 = psVar6, iVar10 <= *(int *)(psVar6 + 0x46))) {
LAB_14004fddd:
          piVar4 = failfastthing(psVar9,iVar10 + -1);
          piVar4[0x30] = 0x68;
          goto LAB_14004fa64;
        }
LAB_1400500e0:
        uVar2 = 0x5dd;
        break;
      }
      if (local_64 != 0x41) {
        if (local_64 == 0x42) {
          if (hMem == (short *)0x0) goto LAB_1400500e0;
          FUN_1400541c0(psVar5,0);
          iVar16 = 0;
          if (hMem_00 == (short *)0x0) goto LAB_1400500c9;
          FUN_1400541c0(psVar6,1);
LAB_14004fa64:
          iVar16 = 0;
          goto LAB_1400500c9;
        }
        if (local_64 == 0x50) {
          local_res20 = (int)DAT_1400a97b0;
          iVar16 = iVar15;
          goto LAB_1400500c9;
        }
        if (local_64 != 0x51) {
          if (local_64 == 0x53) {
            if ((hMem_00 == (short *)0x0) || (!bVar1)) {
              if ((hMem != (short *)0x0) &&
                 ((0 < iVar12 &&
                  (psVar9 = psVar5, iVar10 = iVar12, iVar12 <= *(int *)(psVar5 + 0x46)))))
              goto LAB_14004fb79;
            }
            else if ((0 < iVar10) && (psVar9 = psVar6, iVar10 <= *(int *)(psVar6 + 0x46))) {
LAB_14004fb79:
              piVar4 = failfastthing(psVar9,iVar10 + -1);
              FUN_140054444((longlong)piVar4,0x1400a97b0);
              goto LAB_14004fa64;
            }
          }
          else {
            if (local_64 != 0x54) {
              iVar16 = 0;
              if (local_64 == 0x56) {
                if ((hMem_00 == (short *)0x0) || (!bVar1)) {
                  if ((hMem == (short *)0x0) || ((iVar12 < 1 || (*(int *)(psVar5 + 0x46) < iVar12 )))
                     ) goto LAB_1400500e0;
                  iVar16 = iVar15;
                  if (iVar12 < *(int *)(psVar5 + 0x4e)) {
                    lVar3 = (longlong)psVar5 + (longlong)*(int *)(psVar5 + 0x50);
                    goto LAB_14004fa56;
                  }
                }
                else {
                  if ((iVar10 < 1) || (*(int *)(psVar6 + 0x46) < iVar10)) goto LAB_1400500e0;
                  if (iVar10 < *(int *)(psVar6 + 0x4e)) {
                    lVar3 = (longlong)psVar6 + (longlong)*(int *)(psVar6 + 0x50);
                    iVar12 = iVar10;
LAB_14004fa56:
                    FUN_140054854(lVar3 + (longlong)iVar12 * 0x14,(uint *)0x0,(uint *)0x0);
                    goto LAB_14004fa64;
                  }
                }
              }
              goto LAB_1400500c9;
            }
            if ((hMem_00 == (short *)0x0) || (!bVar1)) {
              if ((hMem != (short *)0x0) && ((0 < iVar12 && (iVar12 <= *(int *)(psVar5 + 0x46)))) ) {
                piVar4 = failfastthing(psVar5,iVar12 + -1);
                psVar9 = psVar5;
                goto LAB_14004fadc;
              }
            }
            else if ((0 < iVar10) && (iVar10 <= *(int *)(psVar6 + 0x46))) {
              piVar4 = failfastthing(psVar6,iVar10 + -1);
              psVar9 = psVar6;
LAB_14004fadc:
              piVar4[0x12] = ((uint)(ushort)DAT_1400a97b6 * 0x90) / DAT_1400980b8;
              piVar4[0x13] = ((uint)DAT_1400a97b6._2_2_ * 0x90) / DAT_1400980b8;
              FUN_140054240(psVar9,0x1400a97b0);
              goto LAB_14004fa64;
            }
          }
          goto LAB_1400500e0;
        }
        if (hMem == (short *)0x0) goto LAB_1400500c0;
        local_68 = 1;
        if ((hMem_00 == (short *)0x0) || ((short)DAT_1400a97b2 != 2)) {
          piVar4 = failfastthing(psVar5,iVar12);
          psVar13 = (short *)(ulonglong)(iVar12 + 1);
          bVar1 = false;
          piVar4[0x1b] = local_res20;
          psVar9 = psVar5;
          iVar10 = local_60;
        }
        else {
          piVar4 = failfastthing(psVar6,iVar10);
          psVar11 = (short *)(ulonglong)(iVar10 + 1);
          bVar1 = true;
          piVar4[0x1b] = local_res20;
          psVar9 = psVar6;
        }
        uVar7 = FUN_1400548fc(psVar9,iVar10);
        uVar2 = (uint)uVar7;
LAB_1400500c5:
        iVar14 = 0;
        iVar16 = 0;
        if (uVar2 == 0) goto LAB_1400500c9;
        break;
      }
      if (local_68 == 0) goto LAB_1400500ec;
      if (hMem_00 == (short *)0x0) {
        if (hMem != (short *)0x0) {
          uVar7 = FUN_14004f868((longlong)psVar5);
          uVar2 = (uint)uVar7;
          GlobalUnlock(hMem);
          if (uVar2 == 0) goto LAB_14004fce8;
          goto LAB_1400500f1;
        }
      }
      else {
        *(int *)(psVar5 + 0x16) = (int)*psVar6;
        *(int *)(psVar5 + 0x18) = *(int *)(psVar6 + 0x46) + -1;
        uVar7 = FUN_14004f868((longlong)psVar6);
        uVar2 = (uint)uVar7;
        GlobalUnlock(hMem_00);
        if (uVar2 != 0) goto LAB_1400500f1;
        uVar7 = FUN_140054b28(window_lock_bullshit,hMem_00);
        local_58 = (short *)0x0;
        if ((int)uVar7 != 0) {
          return uVar7;
        }
        GlobalUnlock(hMem);
LAB_14004fce8:
        uVar7 = FUN_140054b28(window_lock_bullshit,hMem);
        if ((int)uVar7 != 0) {
          return uVar7;
        }
      }
      uVar7 = FUN_140053dbc(window_lock_bullshit,(longlong *)local_50,0);
      if ((int)uVar7 != 0) {
        return uVar7;
      }
      uVar7 = FUN_140053dbc(window_lock_bullshit,(longlong *)&local_58,1);
      hMem = local_50[0];
      if ((int)uVar7 != 0) {
        return uVar7;
      }
      psVar5 = (short *)GlobalLock(local_50[0]);
      hMem_00 = local_58;
      if (local_58 != (short *)0x0) {
        psVar6 = (short *)GlobalLock(local_58);
      }
      psVar11 = (short *)0x0;
      local_68 = 0;
      bVar1 = false;
      local_res20 = 0;
      uVar2 = 0;
      psVar13 = psVar11;
      iVar16 = 0;
    }
    else {
      if (local_64 == 0x88) {
        if ((hMem_00 == (short *)0x0) || (!bVar1)) {
          if (hMem == (short *)0x0) goto LAB_1400500c0;
          if ((0 < iVar12) && (psVar9 = psVar5, iVar10 = iVar12, iVar12 <= *(int *)(psVar5 + 0x46 )))
          goto LAB_140050098;
        }
        else if ((0 < iVar10) && (psVar9 = psVar6, iVar10 <= *(int *)(psVar6 + 0x46))) {
LAB_140050098:
          piVar4 = failfastthing(psVar9,iVar10 + -1);
          piVar4[0xb] = piVar4[0xb] | 1;
          goto LAB_14004fa64;
        }
        goto LAB_1400500e0;
      }
      if (local_64 == 0x92) {
        if ((hMem_00 == (short *)0x0) || (!bVar1)) {
          if ((hMem != (short *)0x0) &&
             ((0 < iVar12 && (psVar9 = psVar5, iVar10 = iVar12, iVar12 <= *(int *)(psVar5 + 0x46) )))
             ) goto LAB_14005003b;
        }
        else if ((0 < iVar10) && (psVar9 = psVar6, iVar10 <= *(int *)(psVar6 + 0x46))) {
LAB_14005003b:
          piVar4 = failfastthing(psVar9,iVar10 + -1);
          FUN_140054300((longlong)piVar4,0x1400a97b0);
          goto LAB_14004fa64;
        }
        goto LAB_1400500e0;
      }
      if (local_64 == 0x93) {
        if (hMem == (short *)0x0) goto LAB_1400500e0;
        FUN_14005439c((undefined4 *)(psVar5 + 0x58),0x1400a97b0);
        if (hMem_00 != (short *)0x0) {
          FUN_14005439c((undefined4 *)(psVar6 + 0x58),0x1400a97b0);
        }
      }
      else {
        if (local_64 == 0x9a) {
          if ((hMem_00 == (short *)0x0) || (!bVar1)) {
            if ((hMem != (short *)0x0) && ((0 < iVar12 && (iVar12 <= *(int *)(psVar5 + 0x46))))) {
              piVar4 = failfastthing(psVar5,iVar12 + -1);
              uVar8 = piVar4[0x3d];
              if ((short)DAT_1400a97b2 == 0) goto LAB_14004ff7b;
              uVar8 = uVar8 | 0x200;
              goto LAB_14004ff70;
            }
          }
          else if ((0 < iVar10) && (iVar10 <= *(int *)(psVar6 + 0x46))) {
            piVar4 = failfastthing(psVar6,iVar10 + -1);
            uVar8 = piVar4[0x3d];
            if ((short)DAT_1400a97b2 == 0) {
LAB_14004ff7b:
              iVar16 = 0;
              if ((uVar8 & 0x200) == 0) goto LAB_1400500c9;
              uVar8 = uVar8 ^ 0x200;
            }
            else {
              uVar8 = uVar8 | 0x200;
            }
LAB_14004ff70:
            piVar4[0x3d] = uVar8;
            iVar16 = 0;
            goto LAB_1400500c9;
          }
          goto LAB_1400500e0;
        }
        if (local_64 == 0x4008) {
          if ((hMem_00 == (short *)0x0) || (!bVar1)) {
            if ((hMem != (short *)0x0) &&
               ((0 < iVar12 && (psVar9 = psVar5, iVar10 = iVar12, iVar12 <= *(int *)(psVar5 + 0x4 6))
                ))) goto LAB_14004ff01;
          }
          else if ((0 < iVar10) && (psVar9 = psVar6, iVar10 <= *(int *)(psVar6 + 0x46))) {
LAB_14004ff01:
            piVar4 = failfastthing(psVar9,iVar10 + -1);
            uVar7 = FUN_1400504c4(window_lock_bullshit,piVar4[4],filehandle);
            uVar2 = (uint)uVar7;
            goto LAB_1400500c5;
          }
LAB_1400500c0:
          uVar2 = 0x5dd;
          goto LAB_1400500c5;
        }
        iVar16 = iVar15;
        if (local_64 == 0x400c) {
          if ((hMem_00 == (short *)0x0) || (!bVar1)) {
            if (hMem == (short *)0x0) goto LAB_1400500c0;
            if ((0 < iVar12) && (psVar9 = psVar5, iVar12 <= *(int *)(psVar5 + 0x46)))
            goto LAB_14004fe9b;
          }
          else if ((0 < iVar10) && (psVar9 = psVar6, iVar10 <= *(int *)(psVar6 + 0x46))) {
LAB_14004fe9b:
            uVar2 = FUN_140051970((longlong)psVar9,filehandle);
            goto LAB_1400500c5;
          }
        }
      }
    }
LAB_1400500c9:
    iVar14 = iVar16;
  } while (local_64 != 0x6006);
  if (local_68 == iVar14) {
LAB_1400500ec:
    uVar2 = 0x5dd;
  }
  else if (uVar2 == 0) {
    if (hMem_00 == (short *)0x0) {
      if (hMem == (short *)0x0) goto LAB_1400500f1;
      uVar7 = FUN_14004f868((longlong)psVar5);
      uVar2 = (uint)uVar7;
      GlobalUnlock(hMem);
      if (uVar2 != 0) goto LAB_1400500f1;
    }
    else {
      *(int *)(psVar5 + 0x16) = (int)*psVar6;
      *(int *)(psVar5 + 0x18) = *(int *)(psVar6 + 0x46) + -1;
      uVar7 = FUN_14004f868((longlong)psVar6);
      uVar2 = (uint)uVar7;
      GlobalUnlock(hMem_00);
      if (uVar2 != 0) goto LAB_1400500f1;
      uVar7 = FUN_140054b28(window_lock_bullshit,hMem_00);
      if ((int)uVar7 != 0) {
        return uVar7;
      }
      GlobalUnlock(hMem);
    }
    uVar7 = FUN_140054b28(window_lock_bullshit,hMem);
    uVar2 = (uint)uVar7;
    if (uVar2 != 0) {
      return uVar7;
    }
  }
LAB_1400500f1:
  return (ulonglong)uVar2;
}



```

here:

```

        if ((hMem_00 == (short *)0x0) || ((short)DAT_1400a97b2 != 2)) {
          piVar4 = failfastthing(psVar5,iVar12);
          psVar13 = (short *)(ulonglong)(iVar12 + 1);
          bVar1 = false;
          piVar4[0x1b] = local_res20;
          psVar9 = psVar5;
          iVar10 = local_60;
        }

```

So i think that the check is just there for some size calculation or some bullshit like that.

I wasn't actually able to get the afl-fuzz to work with this, because the harness didn't want to cooperate with me, so I just wrote up a dumb fuzzer and found a crash that way.













