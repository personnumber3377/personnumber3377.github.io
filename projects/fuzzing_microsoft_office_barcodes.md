# Fuzzing microsoft office barcodes

There is a component in microsoft office which is called `MSBARCODE.DLL` which handles a very obscure functionality in the office suite mainly handling barcodes.

Here is a somewhat working program which renders a barcode and then saves it in a file in c++:

```

#include <windows.h>
#include <iostream>
#include <gdiplus.h>
using namespace Gdiplus;
typedef int (__stdcall *GetBarcodeRenderer_t)(int, void**); // Define function signature
typedef long (__thiscall *ValidateDataFunc)(void*, wchar_t*);
// typedef long (__thiscall *DrawToDCFunc)(void*, HDC*, RECT*, wchar_t*);
typedef long (__thiscall *DrawToDCFunc)(void*, HDC, RECT*, wchar_t*);


// #define BARCODE_TYPE 3 // 3 means EAN-8 and 7 means Code128   // Example: barcode type 3 (EAN-8)

#define BARCODE_TYPE 7

struct Example {
    void (*func)(wchar_t *data); // This is the prototype of Code128Renderer::ValidateData which only takes a wchar string pointing to the data...
};


int GetEncoderClsid(const WCHAR* format, CLSID* pClsid) {
    UINT num = 0;          // Number of encoders
    UINT size = 0;         // Size of the image codec info array

    // Get the list of image encoders
    GetImageEncodersSize(&num, &size);
    if (size == 0) return -1;  // No encoders found

    ImageCodecInfo* pImageCodecInfo = (ImageCodecInfo*)(malloc(size));
    if (!pImageCodecInfo) return -1;

    GetImageEncoders(num, size, pImageCodecInfo);

    // Find the correct encoder for the given format
    for (UINT i = 0; i < num; i++) {
        if (wcscmp(pImageCodecInfo[i].MimeType, format) == 0) {
            *pClsid = pImageCodecInfo[i].Clsid;
            free(pImageCodecInfo);
            return 0;  // Success
        }
    }

    free(pImageCodecInfo);
    return -1;  // Encoder not found
}




int main() {
    // This is just some test string:
    // wchar_t *test_str = L"Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!";
    wchar_t *test_str = L"Hello, world!\0";
    // Load the DLL
    HMODULE hDll = LoadLibrary("MSBARCODE.dll");
    if (!hDll) {
        std::cerr << "Failed to load DLL\n";
        return 1;
    }
    // Get function pointer
    GetBarcodeRenderer_t GetBarcodeRenderer =
        (GetBarcodeRenderer_t) GetProcAddress(hDll, "GetBarcodeRenderer");
    if (!GetBarcodeRenderer) {
        std::cerr << "Failed to get function address\n";
        FreeLibrary(hDll);
        return 1;
    }
    // Call the function
    void* renderer = nullptr;
    printf("Here is the value of the barcode renderer before: %d\n", renderer);
    int result = GetBarcodeRenderer(BARCODE_TYPE, &renderer);
    std::cout << "Function returned: " << std::hex << result << "\n";
    printf("Here is the value of the barcode renderer: %p\n", renderer);
    if ((uintptr_t)result > 0x80000000) {
        printf("Error: GetBarcodeRenderer failed with code: 0x%lX\n", (uintptr_t)result);
        return 1;
    }
    if (result) {
        printf("Exiting...\n");
        return 1;
    }

    // Now try to call the verifying of the data stuff...
    printf("Now we should do the stuff\n");
    // ValidateDataFunc func = *(ValidateDataFunc *)((char *)renderer + 0x30);
    // printf("Function pointer at offset 0x30: %p\n", *(void **)((char *)renderer + 0x30));


    void* vtable_ptr = *(void**)renderer;
    int function_offset = 8*5; // At index 5
    int draw_function_offset = 8*7; // At index 7 I think...
    ValidateDataFunc func = *(ValidateDataFunc *)((char *)vtable_ptr+function_offset);


    printf("Function pointer at offset 0x30: %p\n", *(void **)((char *)vtable_ptr+function_offset));

    DrawToDCFunc draw_func = *(DrawToDCFunc *)((char *)vtable_ptr + draw_function_offset);
    printf("DrawToDC function pointer: %p\n", draw_func);

    printf("Dumping vtable:\n");
    for (int i = 0; i < 10; i++) {
        printf("vtable[%d] = %p\n", i, *(void **)((char *)vtable_ptr + i * sizeof(void *)));
    }
    printf("Calling the stuff...\n");
    long res = func(vtable_ptr, test_str);
    printf("Returned...\n");
    printf("Returned this value here: 0x%llx\n", res);
    // Free the DLL



    HDC hdcMem = CreateCompatibleDC(NULL);  // Create a memory DC
    if (!hdcMem) {
        printf("Error: Could not create memory DC!\n");
        return 1;
    }

    // Define the barcode dimensions
    int width = 300;   // Set barcode width
    int height = 100;  // Set barcode height
    HBITMAP hBitmap = CreateCompatibleBitmap(hdcMem, width, height);
    SelectObject(hdcMem, hBitmap);  // Select the bitmap into the memory DC

    // Define the drawing rectangle
    RECT rect = {0, 0, width, height};

    // Call `DrawToDC`
    long res2 = draw_func(renderer, hdcMem, &rect, test_str);
    printf("DrawToDC returned: 0x%lX\n", res2);





    /*

    // Initialize GDI+
    GdiplusStartupInput gdiplusStartupInput;
    ULONG_PTR gdiplusToken;
    GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);

    // Convert HBITMAP to a GDI+ Bitmap
    Bitmap bmp(hBitmap, NULL);

    // Save the image as a PNG file
    CLSID pngClsid;
    GetEncoderClsid(L"image/png", &pngClsid);
    bmp.Save(L"barcode.png", &pngClsid, NULL);

    // Clean up
    DeleteObject(hBitmap);
    DeleteDC(hdcMem);
    GdiplusShutdown(gdiplusToken);
    */


    GdiplusStartupInput gdiplusStartupInput;
    ULONG_PTR gdiplusToken;
    GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);

    // Create a memory DC and a compatible bitmap
    /*
    HDC hdcMem = CreateCompatibleDC(NULL);
    int width = 300, height = 100;
    HBITMAP hBitmap = CreateCompatibleBitmap(hdcMem, width, height);
    SelectObject(hdcMem, hBitmap);
    */

    // Properly create a new Bitmap from HBITMAP
    Bitmap* bmp = Bitmap::FromHBITMAP(hBitmap, NULL);
    if (!bmp || bmp->GetLastStatus() != Ok) {
        printf("Error: Failed to create Bitmap object!\n");
        return 1;
    }

    // Save as PNG
    CLSID pngClsid;
    if (GetEncoderClsid(L"image/png", &pngClsid) != 0) {
        printf("Error: Could not find PNG encoder!\n");
        return 1;
    }
    bmp->Save(L"barcode.png", &pngClsid, NULL);

    // Cleanup
    DeleteObject(hBitmap);
    DeleteDC(hdcMem);
    delete bmp; // Properly free Bitmap

    GdiplusShutdown(gdiplusToken);

    printf("Barcode saved as 'barcode.png'\n");


    FreeLibrary(hDll);
    return 0;
}


```

Now let's clean it up a little and also implement some of the other formats... I think I also need to free the actual renderer by calling the function at offset 0 from the base because looking at the decompilation that destroys it. Here is the decompiled code stuff:

```

undefined8 * GetBarcodeRenderer(int param_1,undefined8 *param_2)

{
  undefined8 *puVar1;
  undefined8 *puVar2;
  undefined **ppuVar3;
  undefined8 *puVar4;

                    /* 0x1e70  1  GetBarcodeRenderer */
  puVar4 = (undefined8 *)0x0;
  if (param_2 == (undefined8 *)0x0) {
    return (undefined8 *)0x80004003;
  }
  puVar2 = puVar4;
  if (param_1 < 7) {
    if (param_1 == 6) {
      puVar1 = (undefined8 *)malloc(0x30);
      if (puVar1 == (undefined8 *)0x0) goto LAB_180002141;
      *(undefined4 *)(puVar1 + 1) = 6;
      ppuVar3 = &Code39Renderer::`vftable';
LAB_180001ef3:
      *(undefined4 *)(puVar1 + 5) = 0;
    }
    else if (param_1 == 0) {
      puVar1 = (undefined8 *)malloc(0x30);
      if (puVar1 == (undefined8 *)0x0) goto LAB_180002141;
      *(undefined4 *)(puVar1 + 1) = 0;
      ppuVar3 = &UPCARenderer::`vftable';
      *(undefined4 *)(puVar1 + 5) = 0;
    }
    else if (param_1 == 1) {
      puVar1 = (undefined8 *)malloc(0x30);
      if (puVar1 == (undefined8 *)0x0) goto LAB_180002141;
      *(undefined4 *)(puVar1 + 1) = 1;
      ppuVar3 = &UPCERenderer::`vftable';
      *(undefined4 *)(puVar1 + 5) = 0;
    }
    else if (param_1 == 2) {
      puVar1 = (undefined8 *)malloc(0x30);
      if (puVar1 == (undefined8 *)0x0) goto LAB_180002141;
      *(undefined4 *)(puVar1 + 1) = 2;
      ppuVar3 = &EAN13Renderer::`vftable';
      *(undefined4 *)(puVar1 + 5) = 0;
    }
    else {
      if (param_1 != 3) {
        if (param_1 == 4) {
          puVar1 = (undefined8 *)malloc(0x30);
          if (puVar1 == (undefined8 *)0x0) goto LAB_180002141;
          *(undefined4 *)(puVar1 + 1) = 4;
          ppuVar3 = &CaseRenderer::`vftable';
        }
        else {
          if (param_1 != 5) {
            return (undefined8 *)0x8004ef00;
          }
          puVar1 = (undefined8 *)malloc(0x30);
          if (puVar1 == (undefined8 *)0x0) goto LAB_180002141;
          *(undefined4 *)(puVar1 + 1) = 5;
          ppuVar3 = &NW7Renderer::`vftable';
        }
        goto LAB_180001ef3;
      }
      puVar1 = (undefined8 *)malloc(0x30);
      if (puVar1 == (undefined8 *)0x0) goto LAB_180002141;
      *(undefined4 *)(puVar1 + 1) = 3;
      ppuVar3 = &EAN8Renderer::`vftable';
      *(undefined4 *)(puVar1 + 5) = 0;
    }
  }
  else {
    if (param_1 != 7) {
      if (param_1 == 8) {
        puVar1 = (undefined8 *)malloc(0x30);
        if (puVar1 == (undefined8 *)0x0) goto LAB_180002141;
        puVar1[1] = 8;
        ppuVar3 = &PostnetRenderer::`vftable';
      }
      else {
        if (param_1 != 9) {
          if (param_1 == 10) {
            puVar1 = (undefined8 *)malloc(0x28);
            if (puVar1 != (undefined8 *)0x0) {
              puVar1[1] = 10;
              *puVar1 = &JPPostRenderer::`vftable';
              puVar1[2] = 2;
              *(undefined4 *)(puVar1 + 3) = 0;
              *(undefined8 *)((longlong)puVar1 + 0x1c) = 0xffffff;
              puVar2 = puVar1;
            }
            goto LAB_180002141;
          }
          if (param_1 != 0xb) {
            return (undefined8 *)0x8004ef00;
          }
          puVar1 = (undefined8 *)malloc(0x1870);
          if (puVar1 == (undefined8 *)0x0) goto LAB_180002141;
          *(undefined4 *)(puVar1 + 1) = 0xb;
          ppuVar3 = &QRRenderer::`vftable';
          *(undefined4 *)(puVar1 + 5) = 0;
          *(undefined8 *)((longlong)puVar1 + 0x2c) = 2;
          puVar1[7] = 0;
          puVar1[8] = 0;
          puVar1[9] = 0;
          *(undefined4 *)(puVar1 + 0xb) = 0;
          *(undefined2 *)(puVar1 + 0xe) = 0;
          goto LAB_18000211f;
        }
        puVar1 = (undefined8 *)malloc(0x30);
        if (puVar1 == (undefined8 *)0x0) goto LAB_180002141;
        puVar1[1] = 9;
        ppuVar3 = &FIMRenderer::`vftable';
      }
      *(undefined4 *)((longlong)puVar1 + 0x1c) = 0xffffff;
      *(undefined4 *)(puVar1 + 3) = 0;
      puVar1[2] = 2;
      *puVar1 = ppuVar3;
      *(undefined4 *)(puVar1 + 5) = 0;
      *(undefined4 *)(puVar1 + 4) = 2;
      puVar2 = puVar1;
      goto LAB_180002141;
    }
    puVar1 = (undefined8 *)malloc(0x28);
    if (puVar1 == (undefined8 *)0x0) goto LAB_180002141;
    *(undefined4 *)(puVar1 + 1) = 7;
    ppuVar3 = &Code128Renderer::`vftable';
  }
LAB_18000211f:
  *puVar1 = ppuVar3;
  *(undefined8 *)((longlong)puVar1 + 0x1c) = 0xffffff;
  *(undefined4 *)(puVar1 + 3) = 0;
  puVar1[2] = 2;
  *(undefined4 *)((longlong)puVar1 + 0xc) = 1;
  puVar2 = puVar1;
LAB_180002141:
  puVar1 = (undefined8 *)0x8007000e;
  if (puVar2 != (undefined8 *)0x0) {
    *param_2 = puVar2;
    puVar1 = puVar4;
  }
  return puVar1;
}

```

now let's define each one of these things and see what happens...

Now my current fuzzing harness looks like this here:

```

#include <windows.h>
#include <iostream>
#include <gdiplus.h>
using namespace Gdiplus;
typedef int (__stdcall *GetBarcodeRenderer_t)(int, void**); // Define function signature
typedef long (__thiscall *ValidateDataFunc)(void*, wchar_t*);
// typedef long (__thiscall *DrawToDCFunc)(void*, HDC*, RECT*, wchar_t*);
typedef long (__thiscall *DrawToDCFunc)(void*, HDC, RECT*, wchar_t*);

typedef void (__thiscall *DestroyFunc)(void*);  // Function prototype


// #define BARCODE_TYPE 3 // 3 means EAN-8 and 7 means Code128   // Example: barcode type 3 (EAN-8)

#define BARCODE_TYPE 7

struct Example {
    void (*func)(wchar_t *data); // This is the prototype of Code128Renderer::ValidateData which only takes a wchar string pointing to the data...
};


int GetEncoderClsid(const WCHAR* format, CLSID* pClsid) {
    UINT num = 0;          // Number of encoders
    UINT size = 0;         // Size of the image codec info array

    // Get the list of image encoders
    GetImageEncodersSize(&num, &size);
    if (size == 0) return -1;  // No encoders found

    ImageCodecInfo* pImageCodecInfo = (ImageCodecInfo*)(malloc(size));
    if (!pImageCodecInfo) return -1;

    GetImageEncoders(num, size, pImageCodecInfo);

    // Find the correct encoder for the given format
    for (UINT i = 0; i < num; i++) {
        if (wcscmp(pImageCodecInfo[i].MimeType, format) == 0) {
            *pClsid = pImageCodecInfo[i].Clsid;
            free(pImageCodecInfo);
            return 0;  // Success
        }
    }

    free(pImageCodecInfo);
    return -1;  // Encoder not found
}

/*

BARCODE_TYPE 6 is Code39Renderer and it follows the usual convention...

BARCODE_TYPE 0 is UPCARenderer and it also follows the usual convention.

BARCODE_TYPE 1 is UPCERenderer and it follows the usual thing...

BARCODE_TYPE 2 is EAN13Renderer and it also follows the usual stuff...

BARCODE_TYPE 4 is CaseRenderer and it also follows the usual stuff...

BARCODE_TYPE 5 is NW7Renderer and it also follows the usual stuff...

BARCODE_TYPE 3 is EAN8Renderer and it also follows the usual stuff...

BARCODE_TYPE 8 is PostnetRenderer and it follows this stuff here:

                             *************************************************************
                             *  const PostnetRenderer::`vftable'
                             *************************************************************
                             ??_7PostnetRenderer@@6B@                        XREF[2]:     GetBarcodeRenderer:1800020d1 (*)
                             PostnetRenderer::`vftable'                                   GetBarcodeRenderer:1800020f8 (*)
       18000a728 c0  1d  00       addr       BarcodeRendererBase::Destroy
                 80  01  00
                 00  00
       18000a730 e0  1d  00       addr       BarcodeRendererBase::GetType
                 80  01  00
                 00  00
       18000a738 20  5d  00       addr       PostnetRenderer::GetProperty
                 80  01  00
                 00  00
       18000a740 50  5d  00       addr       PostnetRenderer::SetProperty
                 80  01  00
                 00  00
       18000a748 d0  35  00       addr       FIMRenderer::GetMinSize
                 80  01  00
                 00  00
       18000a750 d0  35  00       addr       FIMRenderer::GetMinSize
                 80  01  00
                 00  00
       18000a758 80  5c  00       addr       PostnetRenderer::Draw
                 80  01  00
                 00  00
       18000a760 20  22  00       addr       BarcodeRendererBase::DrawToDC
                 80  01  00
                 00  00
       18000a768 f0  1d  00       addr       NW7Renderer::`vector_deleting_destructor'
                 80  01  00
                 00  00
       18000a770 a0  ca  00       addr       JPPostRenderer::`RTTI_Complete_Object_Locator'   = 01h
                 80  01  00
                 00  00


BARCODE_TYPE 10 is JPPostRenderer is the usual stuff...

BARCODE_TYPE 9 is FIMRenderer and it follows this:


                             *************************************************************
                             *  const FIMRenderer::`vftable'
                             *************************************************************
                             ??_7FIMRenderer@@6B@                            XREF[2]:     GetBarcodeRenderer:1800020b8 (*)
                             FIMRenderer::`vftable'                                       GetBarcodeRenderer:1800020d1 (*)
       18000a6d8 c0  1d  00       addr       BarcodeRendererBase::Destroy
                 80  01  00
                 00  00
       18000a6e0 e0  1d  00       addr       BarcodeRendererBase::GetType
                 80  01  00
                 00  00
       18000a6e8 70  35  00       addr       FIMRenderer::GetProperty
                 80  01  00
                 00  00
       18000a6f0 a0  35  00       addr       FIMRenderer::SetProperty
                 80  01  00
                 00  00
       18000a6f8 d0  35  00       addr       FIMRenderer::GetMinSize
                 80  01  00
                 00  00
       18000a700 d0  35  00       addr       FIMRenderer::GetMinSize
                 80  01  00
                 00  00
       18000a708 f0  34  00       addr       FIMRenderer::Draw
                 80  01  00
                 00  00
       18000a710 20  22  00       addr       BarcodeRendererBase::DrawToDC
                 80  01  00
                 00  00
       18000a718 f0  1d  00       addr       NW7Renderer::`vector_deleting_destructor'
                 80  01  00
                 00  00
       18000a720 78  ca  00       addr       PostnetRenderer::`RTTI_Complete_Object_Locator   = 01h
                 80  01  00
                 00  00


BARCODE_TYPE 11 is QRRenderer and it follows the usual stuff...

so the only barcode types which we need to be wary of are type == 9 and type == 8 because those are special cases where the thing is not where it should be. I think those are used internally, because there is no way to activate those functions from ms word anyway, so I think I am just going to ban those two and see what happens... since the maximum barcode type is 11 we are just going to do modulo 12 and be done with it...





*/


int main() {
    // This is just some test string:
    // wchar_t *test_str = L"Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!";
    wchar_t *test_str = L"Hello, world!\0";
    // Load the DLL
    HMODULE hDll = LoadLibrary("MSBARCODE.dll");
    if (!hDll) {
        std::cerr << "Failed to load DLL\n";
        return 1;
    }
    // Get function pointer
    GetBarcodeRenderer_t GetBarcodeRenderer =
        (GetBarcodeRenderer_t) GetProcAddress(hDll, "GetBarcodeRenderer");
    if (!GetBarcodeRenderer) {
        std::cerr << "Failed to get function address\n";
        FreeLibrary(hDll);
        return 1;
    }
    // Call the function
    void* renderer = nullptr;
    printf("Here is the value of the barcode renderer before: %d\n", renderer);
    int result = GetBarcodeRenderer(BARCODE_TYPE, &renderer);
    std::cout << "Function returned: " << std::hex << result << "\n";
    printf("Here is the value of the barcode renderer: %p\n", renderer);
    if ((uintptr_t)result > 0x80000000) {
        printf("Error: GetBarcodeRenderer failed with code: 0x%lX\n", (uintptr_t)result);
        return 1;
    }
    if (result) {
        printf("Exiting...\n");
        return 1;
    }

    // Now try to call the verifying of the data stuff...
    printf("Now we should do the stuff\n");
    // ValidateDataFunc func = *(ValidateDataFunc *)((char *)renderer + 0x30);
    // printf("Function pointer at offset 0x30: %p\n", *(void **)((char *)renderer + 0x30));


    void* vtable_ptr = *(void**)renderer;
    int function_offset = 8*5; // At index 5
    int draw_function_offset = 8*7; // At index 7 I think...
    ValidateDataFunc func = *(ValidateDataFunc *)((char *)vtable_ptr+function_offset);


    printf("Function pointer at offset 0x30: %p\n", *(void **)((char *)vtable_ptr+function_offset));

    DrawToDCFunc draw_func = *(DrawToDCFunc *)((char *)vtable_ptr + draw_function_offset);
    printf("DrawToDC function pointer: %p\n", draw_func);

    printf("Dumping vtable:\n");
    for (int i = 0; i < 10; i++) {
        printf("vtable[%d] = %p\n", i, *(void **)((char *)vtable_ptr + i * sizeof(void *)));
    }
    printf("Calling the stuff...\n");
    long res = func(vtable_ptr, test_str);
    if (res != 0) {
        // Invalid data. Return here.
        printf("Invalid data passed. Returning...\n");
        return 1;
    }
    printf("Returned...\n");
    printf("Returned this value here: 0x%llx\n", res);
    // Free the DLL



    HDC hdcMem = CreateCompatibleDC(NULL);  // Create a memory DC
    if (!hdcMem) {
        printf("Error: Could not create memory DC!\n");
        return 1;
    }

    // Define the barcode dimensions
    int width = 300;   // Set barcode width
    int height = 100;  // Set barcode height
    HBITMAP hBitmap = CreateCompatibleBitmap(hdcMem, width, height);
    SelectObject(hdcMem, hBitmap);  // Select the bitmap into the memory DC

    // Define the drawing rectangle
    RECT rect = {0, 0, width, height};

    // Call `DrawToDC`
    long res2 = draw_func(renderer, hdcMem, &rect, test_str);
    printf("DrawToDC returned: 0x%lX\n", res2);

    GdiplusStartupInput gdiplusStartupInput;
    ULONG_PTR gdiplusToken;
    GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);

    // Properly create a new Bitmap from HBITMAP
    Bitmap* bmp = Bitmap::FromHBITMAP(hBitmap, NULL);
    if (!bmp || bmp->GetLastStatus() != Ok) {
        printf("Error: Failed to create Bitmap object!\n");
        return 1;
    }

    // Save as PNG
    CLSID pngClsid;
    if (GetEncoderClsid(L"image/png", &pngClsid) != 0) {
        printf("Error: Could not find PNG encoder!\n");
        return 1;
    }
    bmp->Save(L"barcode.png", &pngClsid, NULL);

    // Cleanup
    DeleteObject(hBitmap);
    DeleteDC(hdcMem);
    delete bmp; // Properly free Bitmap

    GdiplusShutdown(gdiplusToken);

    printf("Barcode saved as 'barcode.png'\n");
    printf("Freeing the renderer...\n");
    // *((void*)renderer)(); // Call the renderer free function which is always at index zero...
    DestroyFunc destroy_func = *(DestroyFunc *)((char *)vtable_ptr + 0x0);
    printf("Destroy function pointer: %p\n", destroy_func);

    // Call the function (destroy the object)
    destroy_func(renderer);
    printf("Returned from destroy function...\n");
    FreeLibrary(hDll);
    return 0;
}


```

Here is a fixed up harness:

```

#include <windows.h>
#include <iostream>
#include <vector>
#include <gdiplus.h>

// For input handling
#include <string>
#include <iostream>

using namespace Gdiplus;

#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")

typedef int (__stdcall *GetBarcodeRenderer_t)(int, void**);
typedef long (__thiscall *ValidateDataFunc)(void*, wchar_t*);
typedef long (__thiscall *DrawToDCFunc)(void*, HDC, RECT*, wchar_t*);
typedef void (__thiscall *DestroyFunc)(void*);

// Helper function to get the CLSID of an encoder (e.g., PNG)
int GetEncoderClsid(const WCHAR* format, CLSID* pClsid) {
    UINT num = 0, size = 0;
    GetImageEncodersSize(&num, &size);
    if (size == 0) return -1;

    ImageCodecInfo* pImageCodecInfo = (ImageCodecInfo*)(malloc(size));
    if (!pImageCodecInfo) return -1;

    GetImageEncoders(num, size, pImageCodecInfo);
    for (UINT i = 0; i < num; i++) {
        if (wcscmp(pImageCodecInfo[i].MimeType, format) == 0) {
            *pClsid = pImageCodecInfo[i].Clsid;
            free(pImageCodecInfo);
            return 0;
        }
    }
    free(pImageCodecInfo);
    return -1;
}

int main() {
    // Read input from stdin
    std::string input;
    std::getline(std::cin, input);

    if (input.size() < 2) {  // Need at least 2 bytes (1 for type, rest for barcode data)
        std::cerr << "Error: Input must be at least 2 bytes long!\n";
        return 1;
    }

    // Extract first byte for barcode type and remove it from input
    int barcodeType = static_cast<unsigned char>(input[0]) % 12;
    input = input.substr(1);  // Remove first byte

    // Ban barcode types 8 and 9
    if (barcodeType == 8 || barcodeType == 9) {
        printf("Error: Barcode type %d is banned!\n", barcodeType);
        return 1;
    }

    // Convert remaining input to wide string (wchar_t*)
    std::vector<wchar_t> winput(input.begin(), input.end());
    winput.push_back(L'\0');  // Null-terminate
    wchar_t* test_str = winput.data();

    // Load MSBARCODE.DLL
    // HMODULE hDll = LoadLibrary(L"MSBARCODE.dll");
    HMODULE hDll = LoadLibrary("MSBARCODE.dll");
    if (!hDll) {
        std::cerr << "Failed to load DLL\n";
        return 1;
    }

    // Get function pointer for `GetBarcodeRenderer`
    GetBarcodeRenderer_t GetBarcodeRenderer =
        (GetBarcodeRenderer_t) GetProcAddress(hDll, "GetBarcodeRenderer");

    if (!GetBarcodeRenderer) {
        std::cerr << "Failed to get function address\n";
        FreeLibrary(hDll);
        return 1;
    }

    // Call the function to get the renderer object
    void* renderer = nullptr;
    int result = GetBarcodeRenderer(barcodeType, &renderer);
    if (!renderer) {
        printf("Error: Failed to get barcode renderer!\n");
        FreeLibrary(hDll);
        return 1;
    }

    // Get vtable and function pointers
    void* vtable_ptr = *(void**)renderer;
    int function_offset = 8 * 5;  // At index 5
    int draw_function_offset = 8 * 7;  // At index 7

    ValidateDataFunc validate_func = *(ValidateDataFunc *)((char *)vtable_ptr + function_offset);
    DrawToDCFunc draw_func = *(DrawToDCFunc *)((char *)vtable_ptr + draw_function_offset);
    DestroyFunc destroy_func = *(DestroyFunc *)((char *)vtable_ptr + 0x0);

    if (!validate_func || !draw_func || !destroy_func) {
        printf("Error: Failed to retrieve required function pointers!\n");
        FreeLibrary(hDll);
        return 1;
    }

    // Validate barcode data
    long res = validate_func(renderer, test_str);
    if (res != 0) {
        printf("Invalid data passed. Returning...\n");
        return 1;
    }

    // Create a memory DC
    HDC hdcScreen = GetDC(NULL);
    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    ReleaseDC(NULL, hdcScreen);

    int width = 300, height = 100;
    HBITMAP hBitmap = CreateCompatibleBitmap(hdcMem, width, height);
    SelectObject(hdcMem, hBitmap);

    RECT rect = {0, 0, width, height};

    // Ensure the background is filled
    HBRUSH hBrush = (HBRUSH)GetStockObject(WHITE_BRUSH);
    FillRect(hdcMem, &rect, hBrush);

    // Draw the barcode
    long res2 = draw_func(renderer, hdcMem, &rect, test_str);
    if (res2 != 0) {
        printf("Error: DrawToDC failed! Exiting...\n");
        return 1;
    }

    // Initialize GDI+
    GdiplusStartupInput gdiplusStartupInput;
    ULONG_PTR gdiplusToken;
    GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);

    // Convert HBITMAP to Bitmap
    Bitmap* bmp = Bitmap::FromHBITMAP(hBitmap, NULL);
    if (!bmp || bmp->GetLastStatus() != Ok) {
        printf("Error: Failed to create Bitmap object!\n");
        return 1;
    }

    // Save as PNG
    CLSID pngClsid;
    if (GetEncoderClsid(L"image/png", &pngClsid) != 0) {
        printf("Error: Could not find PNG encoder!\n");
        return 1;
    }
    bmp->Save(L"barcode.png", &pngClsid, NULL);

    // Cleanup
    DeleteObject(hBitmap);
    DeleteDC(hdcMem);
    delete bmp;
    GdiplusShutdown(gdiplusToken);

    // Destroy the renderer
    destroy_func(renderer);

    FreeLibrary(hDll);
    printf("Barcode saved as 'barcode.png'\n");
    return 0;
}

```

now we just need to make the performance a bit better and then writeup a winafl script and start fuzzing!!!


Actually now we have a working fuzzer, but you should check that all of the verifydata functions actually only take the data stuff into them, otherwise you could be in troubel...


















