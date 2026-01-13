# Fuzzing microsofts XML handler

Here is the suspected source code:

{% raw %}
```

void FUN_140001000(void)

{
  bool bVar1;
  DWORD DVar2;
  uint uVar3;
  LPWSTR pWVar4;
  LPWSTR *hMem;
  undefined7 extraout_var;
  undefined7 extraout_var_00;
  wchar_t *pwVar5;
  wchar_t *pwVar6;
  LPWSTR pWVar7;
  int local_18 [4];

  local_18[0] = 0;
  pwVar5 = (wchar_t *)0x0;
  pWVar4 = GetCommandLineW();
  hMem = CommandLineToArgvW(pWVar4,local_18);
  if (hMem == (LPWSTR *)0x0) {
    DVar2 = GetLastError();
    uVar3 = FUN_14000113c(DVar2);
    goto LAB_140001115;
  }
  if (local_18[0] < 2) {
LAB_1400010fa:
    uVar3 = 0x80070057;
  }
  else {
    bVar1 = FUN_140001124(L"/verb",hMem[1]);
    if (((int)CONCAT71(extraout_var,bVar1) == 0) || (pWVar4 = (LPWSTR)0x0, local_18[0] < 4))
    goto LAB_1400010fa;
    pwVar6 = hMem[3];
    pWVar7 = hMem[2];
    uVar3 = 3;
    bVar1 = FUN_140001124(L"/genverb",pwVar6);
    if ((int)CONCAT71(extraout_var_00,bVar1) != 0) {
      if (local_18[0] != 6) goto LAB_1400010fa;
      pWVar4 = hMem[4];
      uVar3 = 5;
    }
    if (uVar3 + 1 != local_18[0]) goto LAB_1400010fa;
    pwVar5 = FUN_1400035d4(hMem[uVar3],(int)pwVar6);
    if (pwVar5 == (wchar_t *)0x0) {
      uVar3 = 0x80004005;
    }
    else {
      FUN_140003d9c(*(LPCWSTR *)pwVar5,(undefined8 *)(pwVar5 + 8));
      if ((*(wchar_t **)(pwVar5 + 8) == (wchar_t *)0x0) && (pWVar4 != (LPWSTR)0x0)) {
        pWVar7 = pWVar4;
      }
      uVar3 = FUN_140004e34(*(LPCWSTR *)pwVar5,*(LPCWSTR *)(pwVar5 + 4),pWVar7,
                            *(wchar_t **)(pwVar5 + 8));
    }
  }
  GlobalFree(hMem);
  if (pwVar5 != (wchar_t *)0x0) {
    xmlFreeNotation((undefined8 *)pwVar5);
  }
LAB_140001115:
                    /* WARNING: Subroutine does not return */
  ExitProcess(uVar3 >> 0x1f);
}

```
{% endraw %}







