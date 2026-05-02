# Fuzzing microsoft svg files again hopefully better this time...

Now, I have fuzzed svg files previously using winafl, but that caused some problems with the integration and stuff like that, now I managed to make it work using litecov and just using python:

```
import zipfile
import shutil
import os
import tempfile
import subprocess
from pathlib import Path
import main
import random
import pyautogui
import time
import pickle
import traceback

# === CONFIG ===

# To gather a corpus or to try to find crashes?
# "crash" / "coverage"
MODE = "coverage"

# MODE = "crash"

TEMPLATE_DOCX = "template.docx"
OUTPUT_DOCX   = "fuzzed.docx"
FUZZ_INPUT = "C:\\Users\\elsku\\svg_custom_mutator\\fuzzed.docx"

NUM_SVGS = 220

WORD_MEDIA_DIR = "word/media"

INIT_CORPUS_DIR = "C:\\Users\\elsku\\svg_corpus\\"
INIT_CORPUS_FILES = os.listdir(INIT_CORPUS_DIR)

INTERESTING_DIRECTORY = "C:\\Users\\elsku\\svg_interesting\\"

CRASHES_DIRECTORY = "C:\\Users\\elsku\\svg_crashes\\"

COVERAGE_FILE = "C:\\Users\\elsku\\svg_custom_mutator\\coverage.bin"
STATE_FILE = "C:\\Users\\elsku\\svg_custom_mutator\\state.pkl"

# === COVERAGE CMD (UNCHANGED) ===
COVERAGE_CMD = [
    "C:\\Users\\elsku\\TinyInst\\build\\Release\\litecov.exe",
    "-instrument_module", "MSOSVG.dll",
    "-coverage_file", COVERAGE_FILE,
    "--",
    "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
    "/n",
    "/q",
    FUZZ_INPUT
]


# This is mainly for actual crash discovery since the coverage mechanism hides a lot of crashes for some reason...
NO_COVERAGE_CMD = [
    "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
    "/n",
    "/q",
    FUZZ_INPUT
]

# === RUNTIME CONFIG ===
SCROLL_DOWN_AMOUNT = -500
STEPS = 50
TIME_STEP = 0.01
PROC_TIMEOUT = 40.0 # 30.0

# === GLOBAL STATE ===
coverage = set()
interesting_corpus = []
initial_corpus = []

# This stuff here is for generating the coverage report into my email...
import time

START_TIME = time.time()
COVERAGE_LOG = "coverage_log.csv"

iterations = 0

def log_coverage():
    elapsed = int(time.time() - START_TIME)
    # cov_size = len(coverage)

    with open(COVERAGE_LOG, "a") as f:
        # f.write(f"{elapsed},{cov_size}\n")
        # iterations
        cov_size = len(coverage)
        f.write(f"{elapsed},{cov_size},{iterations}\n")

def log(string):
    # Logs a string to the log file...
    fh = open("C:\\Users\\elsku\\svg_mutator_log_thing.txt", "a+")
    fh.write("[LOG] "+str(string)+"\n")
    fh.close()

def wait_until_unlocked(path, timeout=5.0):
    start = time.time()
    while time.time() - start < timeout:
        try:
            with open(path, "ab"):
                return True
        except PermissionError:
            time.sleep(0.2)
    return False

def safe_copy(src, dst, retries=10, delay=0.5):
    for attempt in range(retries):
        try:
            shutil.copy(src, dst)
            return
        except PermissionError:
            print(f"[!] Copy failed (locked), retry {attempt+1}")
            time.sleep(delay)
    print("[!] Copy failed permanently")

# === LOAD INITIAL CORPUS INTO MEMORY ===
def load_initial_corpus():
    corpus = []
    for f in INIT_CORPUS_FILES:
        try:
            with open(INIT_CORPUS_DIR + f, "rb") as fh:
                corpus.append(fh.read())
        except:
            pass
    print(f"[+] Loaded {len(corpus)} initial SVGs into memory")
    return corpus

# === STATE SAVE / LOAD ===
def save_state():
    with open(STATE_FILE, "wb") as f:
        pickle.dump({
            "coverage": coverage,
            "interesting_corpus": interesting_corpus
        }, f)
    print("[+] State saved")

def load_state():
    global coverage, interesting_corpus

    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "rb") as f:
            data = pickle.load(f)
            coverage = data["coverage"]
            interesting_corpus = data["interesting_corpus"]
        print("[+] Resumed previous session")

# === DOCX UTIL ===
def unzip_docx(docx_path, extract_dir):
    with zipfile.ZipFile(docx_path, 'r') as zip_ref:
        zip_ref.extractall(extract_dir)
'''
def zip_docx(folder, output_path):
    with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as docx:
        for root, dirs, files in os.walk(folder):
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, folder)
                docx.write(full_path, rel_path)
'''

def zip_docx(folder, output_path, retries=10, delay=0.5):
    for attempt in range(retries):
        try:
            with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as docx:
                for root, dirs, files in os.walk(folder):
                    for file in files:
                        full_path = os.path.join(root, file)
                        rel_path = os.path.relpath(full_path, folder)
                        docx.write(full_path, rel_path)
            return  # success

        except PermissionError as e:
            print(f"[!] Permission denied writing {output_path}, retry {attempt+1}/{retries}")
            time.sleep(delay)

    raise RuntimeError(f"Failed to write {output_path} after retries")

# === SVG GENERATION ===
def generate_svgs(media_dir):
    generated = []
    svg_group = []

    use_interesting = (
        len(interesting_corpus) > 0 and random.random() < 0.8
    )

    for i in range(NUM_SVGS):
        out_svg = media_dir / f"fuzz{i}.svg"

        if use_interesting:
            base_group = random.choice(interesting_corpus)
            base_svg = random.choice(base_group)
        else:
            base_svg = random.choice(initial_corpus)

        success = False
        count = 0

        try:

            # mutated = main.mutate_main(base_svg)

            # Also use crossover too...

            if random.random() < 0.3:
                # --- CROSSOVER ---
                if use_interesting and len(interesting_corpus) > 0:
                    other_group = random.choice(interesting_corpus)
                    other_svg = random.choice(other_group)
                else:
                    other_svg = random.choice(initial_corpus)

                try:
                    mutated = main.crossover_svg(base_svg, other_svg)
                except Exception as e:
                    log(str(e)) # Log the exception...
                    log("Back trace:")
                    tb = traceback.format_exc()
                    log(tb)
                    print("Got this exception here on crossover: "+str(e))
                    mutated = base_svg

            else:
                # --- NORMAL MUTATION ---
                try:
                    mutated = main.mutate_main(base_svg)
                except Exception as e:
                    log(str(e)) # Log the exception...
                    log("Back trace:")
                    tb = traceback.format_exc()
                    log(tb)
                    print("Got this exception here on normal mutation: "+str(e))
                    mutated = base_svg

                success = True
        except:
            # continue
            mutated = base_svg


        with open(out_svg, "wb") as fh:
            fh.write(mutated)

        svg_group.append(mutated)
        generated.append(f"media/fuzz{i}.svg")

    return generated, svg_group

# === BUILD DOCX ===
def build_fuzzed_docx():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        print("[+] Unzipping the template docx...")
        unzip_docx(TEMPLATE_DOCX, tmpdir)

        media_dir = tmpdir / WORD_MEDIA_DIR
        print("[+] Generating the svg files...")
        _, svg_group = generate_svgs(media_dir)
        print("[+] Zipping the docx back...")
        zip_docx(tmpdir, OUTPUT_DOCX)

        print(f"[+] Generated {OUTPUT_DOCX}")

        return svg_group

# === POPUP HANDLER (PIXEL BASED, MINIMAL) ===
def handle_popups():
    try:
        # You NEED to calibrate this pixel once
        x, y = 960, 540
        color = pyautogui.screenshot().getpixel((x, y))

        # crude "blue-ish dialog" detection
        if color[2] > 150 and color[0] < 120:
            print("[!] Popup detected, auto-dismiss")
            pyautogui.press("left")
            pyautogui.press("enter")

    except:
        pass

# This is a helper to just kill all the word processes after a crash such that we start from a clean slate...
'''
def kill_all_word():
    print("[!] Killing all WINWORD processes...")

    try:
        subprocess.run(
            ["taskkill", "/IM", "WINWORD.EXE", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
    except Exception as e:
        print("kill error:", e)

    # small delay to let Windows clean up
    time.sleep(0.5)
'''

def kill_all_word():
    print("[!] Killing all WINWORD processes...")

    try:
        subprocess.run(
            ["taskkill", "/IM", "WINWORD.EXE", "/F", "/T"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
    except Exception as e:
        print("kill error:", e)

    time.sleep(1.0)  # increase delay
    print("[+] Returned from the kill_all_word function!")

# === RUN TARGET ===

def run_program():
    cmd = COVERAGE_CMD if MODE == "coverage" else NO_COVERAGE_CMD

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )

    crash_detected = False
    crash_info = []

    try:
        start_time = time.time()

        while True:
            # === READ OUTPUT (if available) ===
            if proc.stdout and MODE == "coverage": # Check for coverage mode here...
                line = proc.stdout.readline()
                if line:
                    print(line.strip())

                    if (
                        "Process crashed" in line or
                        "Exception at address" in line or
                        "Access address" in line
                    ):
                        crash_detected = True
                        crash_info.append(line.strip())

            # === UI INTERACTION ===
            handle_popups()
            pyautogui.scroll(SCROLL_DOWN_AMOUNT)

            # === TIMEOUT (CRITICAL IN CRASH MODE) ===
            if time.time() - start_time > PROC_TIMEOUT:
                print("[!] Timeout hit -> killing process")
                proc.kill()
                proc.wait(timeout=2)
                kill_all_word()

                # Timeout = interesting in crash mode
                '''
                if MODE == "crash":
                    dst = (
                        CRASHES_DIRECTORY +
                        str(random.randrange(10_000_000)) +
                        "_timeout.docx"
                    )
                    safe_copy(FUZZ_INPUT, dst)
                '''
                return True

            # === PROCESS EXIT CHECK ===
            if proc.poll() is not None:
                break

            time.sleep(TIME_STEP)

        rc = proc.wait()
        print("return code:", rc)

        # === CRASH DETECTION ===
        if crash_detected:
            print("[!!!] CRASH DETECTED")

            suffix = "_".join(crash_info).replace(" ", "_")[:100]

            dst = (
                CRASHES_DIRECTORY +
                str(random.randrange(10_000_000)) +
                "_" + suffix +
                ".docx"
            )

            safe_copy(FUZZ_INPUT, dst)
            kill_all_word()
            return True

        # === NON-ZERO EXIT ===
        if rc != 0:
            print("[!] abnormal exit")

            dst = (
                CRASHES_DIRECTORY +
                str(random.randrange(10_000_000)) +
                "_" + str(hex(rc))[2:] +
                ".docx"
            )

            safe_copy(FUZZ_INPUT, dst)
            kill_all_word()
            return True

        # If the file returns with zero, but without timing out, then it may also be an indicative of a problem...
        if MODE == "crash": # Only check in the crash mode...
            print("[!] exited even though shouldn't")

            dst = (
                CRASHES_DIRECTORY +
                str(random.randrange(10_000_000)) +
                "_" + str(hex(rc))[2:] + "_zeroreturn" +
                ".docx"
            )

            safe_copy(FUZZ_INPUT, dst)
            kill_all_word()
            return True
        return False

    except Exception as e:
        print("run error:", e)
        proc.kill()
        proc.wait(timeout=2)
        kill_all_word()
        return True

    return False

# === COVERAGE PARSER ===
def parse_coverage():
    try:
        with open(COVERAGE_FILE, "r") as fh:
            lines = fh.readlines()
    except:
        return set()

    header = "MSOSVG.dll+"
    cov = set()

    for line in lines:
        if line.startswith(header):
            l = line[len(header):].strip()
            try:
                cov.add(int(l, 16))
            except:
                pass

    return cov

# === COVERAGE UPDATE ===
def update_coverage_and_is_interesting():
    global coverage

    current_coverage = parse_coverage()
    new_coverage = current_coverage - coverage

    print("new_coverage:", new_coverage)

    if new_coverage:
        coverage |= new_coverage
        return True

    return False

# === SAVE INTERESTING DOCX ===
def save_docx_copy():
    dst = INTERESTING_DIRECTORY + str(random.randrange(10_000_000)) + ".docx"
    safe_copy(FUZZ_INPUT, dst)

# === FUZZ LOOP ===
def fuzz():
    iteration = 0
    global iterations
    while True:
        # iterations += 1
        log_coverage()

        print("[+] Killing word")
        kill_all_word()
        print("[+] Waiting for unlocked...")
        wait_until_unlocked(OUTPUT_DOCX)
        print("[+] Building word document...")
        svg_group = build_fuzzed_docx()
        print("[+] Running the microsoft word program...")
        crashed = run_program()
        if not crashed:
            iterations += 1
        print("Crashed: "+str(crashed))
        if MODE == "coverage":
            if crashed:
                continue

            print("Checking coverage...")

            if update_coverage_and_is_interesting():
                print("[+] Interesting sample found!")
                print("Coverage size:", len(coverage))

                interesting_corpus.append(svg_group)
                save_docx_copy()

        else:  # CRASH MODE
            # No coverage logic
            pass

        iteration += 1

        if iteration % 10 == 0:
            save_state()

# === MAIN ===
if __name__ == "__main__":
    initial_corpus = load_initial_corpus()
    load_state()
    fuzz()

```

This works and gets coverage nicely, but it is quite slow since it has to open and close microsoft office on every iteration which causes major slowdown. Now, the current idea is to get the coverage and stuff using this program called "what-the-fuzz" which seems to be a tool for snapshot based fuzzing. Now, first we need to figure out where to get the snapshot when fuzzing svg files. There is this AcquireEffectTree function inside the MSOSVG.DLL file:

```

/* WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall */
/* public: virtual class Ofc::TCntPtr<struct GEL::ITopLevelEffect> __cdecl
   Mso::SVG::SVGImage::AcquireEffectTree(struct Math::TAffine3x3<double> const & __ptr64,struct
   GEL::IColorResolver const * __ptr64)const __ptr64 */

undefined8 * __thiscall
Mso::SVG::SVGImage::AcquireEffectTree
          (SVGImage *this,undefined8 *param_1,undefined8 *param_2,undefined8 param_3)

{
  longlong *plVar1;
  code *pcVar2;
  undefined8 uVar3;
  char cVar4;
  undefined8 *puVar5;
  EnvironmentRenderer *this_00;
  longlong *local_70;
  EnvironmentRenderer *local_68;
  EnvironmentRenderer *local_60;
  undefined8 local_58;
  undefined8 uStack_50;
  undefined8 local_48;
  undefined8 uStack_40;
  undefined8 local_38;
  undefined8 uStack_30;
  undefined8 local_28;
  undefined8 uStack_20;

  local_68 = (EnvironmentRenderer *)Ordinal_52497(0x50);
  if (local_68 == (EnvironmentRenderer *)0x0) {
    Ordinal_59938();
    pcVar2 = (code *)swi(3);
    puVar5 = (undefined8 *)(*pcVar2)();
    return puVar5;
  }
  this_00 = (EnvironmentRenderer *)
            EnvironmentRenderer::EnvironmentRenderer(local_68,*(Environment **)(this + 0x80));
  local_60 = this_00;
  GEL::ITopLevelEffect::Create(param_1,1);
  if ((this_00 != (EnvironmentRenderer *)0x0) &&
     (cVar4 = (**(code **)(*(longlong *)this + 0x38))(this), cVar4 == '\0')) {
    uVar3 = param_2[1];
    *(undefined8 *)(this_00 + 0x10) = *param_2;
    *(undefined8 *)(this_00 + 0x18) = uVar3;
    uVar3 = param_2[3];
    *(undefined8 *)(this_00 + 0x20) = param_2[2];
    *(undefined8 *)(this_00 + 0x28) = uVar3;
    uVar3 = param_2[5];
    *(undefined8 *)(this_00 + 0x30) = param_2[4];
    *(undefined8 *)(this_00 + 0x38) = uVar3;
    (**(code **)(*(longlong *)this + 0x20))(this,&local_68);
    local_58 = 0x3ff0000000000000;
    uStack_50 = 0x3ff0000000000000;
    EnvironmentRenderer::RenderRoot
              (this_00,(longlong *)&local_70,(uint *)&local_68,&local_58,param_3);
    local_48 = 0x40c29a8000000000;
    uStack_40 = 0;
    local_38 = 0;
    uStack_30 = 0x40c29a8000000000;
    local_28 = 0;
    uStack_20 = 0;
    (**(code **)(*(longlong *)*param_1 + 0x78))((longlong *)*param_1,local_70,&local_48);
    plVar1 = *(longlong **)(*(longlong *)(this_00 + 0x40) + 0x210);
    if (plVar1 == (longlong *)0x0) {
LAB_18000529e:
      Ordinal_21217(0x1e3c3840,0);
      pcVar2 = (code *)swi(3);
      puVar5 = (undefined8 *)(*pcVar2)();
      return puVar5;
    }
    (**(code **)*plVar1)(plVar1);
    cVar4 = *(char *)(plVar1 + 0x43);
    (**(code **)(*plVar1 + 8))(plVar1);
    if (cVar4 != '\0') {
      this[0x88] = (SVGImage)0x0;
      plVar1 = *(longlong **)(*(longlong *)(this_00 + 0x40) + 0x210);
      if (plVar1 == (longlong *)0x0) {
        Ordinal_21217(0x1e3c3840,0);
        goto LAB_18000529e;
      }
      (**(code **)*plVar1)(plVar1);
      *(undefined *)(plVar1 + 0x43) = 0;
      (**(code **)(*plVar1 + 8))(plVar1);
    }
    if (local_70 != (longlong *)0x0) {
      (**(code **)(*local_70 + 8))();
    }
  }
  if (this_00 != (EnvironmentRenderer *)0x0) {
    plVar1 = *(longlong **)(this_00 + 0x48);
    if (plVar1 != (longlong *)0x0) {
      *(undefined8 *)(this_00 + 0x48) = 0;
      (**(code **)(*plVar1 + 8))();
    }
    Ordinal_53248(this_00);
  }
  return param_1;
}

```

which seems very promising in terms of fuzzing...

Here in windbg at the start of this function we have this here:

```
Breakpoint 0 hit
msosvg!Mso::SVG::SVGImage::AcquireEffectTree:
00007ffa`fd795080 488bc4          mov     rax,rsp
0:000> r
rax=00007ffafd795080 rbx=000000e3c8d10870 rcx=000002cd79c7cf60
rdx=000000e3c8d0fd90 rsi=000002cd0c360fa0 rdi=000002cda4fe2fd8
rip=00007ffafd795080 rsp=000000e3c8d0fd58 rbp=000000e3c8d0fe60
 r8=000000e3c8d0ff10  r9=000002cd6fc98fe0 r10=00000fff5faf2a10
r11=0000000000010005 r12=000000e3c8d108f0 r13=000000e3c8d10f10
r14=000000e3c8d10720 r15=000002cda4fe2fb8
iopl=0         nv up ei pl zr na pe cy
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000247
msosvg!Mso::SVG::SVGImage::AcquireEffectTree:
00007ffa`fd795080 488bc4          mov     rax,rsp
0:000> u
msosvg!Mso::SVG::SVGImage::AcquireEffectTree:
00007ffa`fd795080 488bc4          mov     rax,rsp
00007ffa`fd795083 48895808        mov     qword ptr [rax+8],rbx
00007ffa`fd795087 48897018        mov     qword ptr [rax+18h],rsi
00007ffa`fd79508b 48897820        mov     qword ptr [rax+20h],rdi
00007ffa`fd79508f 48895010        mov     qword ptr [rax+10h],rdx
00007ffa`fd795093 55              push    rbp
00007ffa`fd795094 4156            push    r14
00007ffa`fd795096 4157            push    r15
0:000> s -a 0 L?7fffffffffff "<svg"
                                  ^ User interrupted operation error in 's -a 0 l?7fffffffffff "<svg'
0:000> s -a 0 L?7fffffffffff "<svg viewbox"
0:000> s -u 0 L?7fffffffffff "<svg viewbox"
                                          ^ User interrupted operation error in 's -u 0 l?7fffffffffff "<svg viewbox'
0:000> s -a 0 L?7fffffffffff "<svg viewBox"
000002cd`44eb0000  3c 73 76 67 20 76 69 65-77 42 6f 78 3d 27 30 20  <svg viewBox='0
00007ffb`0ca4f880  3c 73 76 67 20 76 69 65-77 42 6f 78 3d 22 30 20  <svg viewBox="0
00007ffb`0ca50838  3c 73 76 67 20 76 69 65-77 42 6f 78 3d 22 30 20  <svg viewBox="0
00007ffb`15e92088  3c 73 76 67 20 76 69 65-77 42 6f 78 3d 22 30 20  <svg viewBox="0
0:000> s -u 0 L?7fffffffffff "<svg viewBox"
000002cd`a6694e48  003c 0073 0076 0067 0020 0076 0069 0065  <.s.v.g. .v.i.e.
```

then trying to do the stuff here:

```
0:000> s -u 0 L?7fffffffffff "<svg viewBox"
000002cd`a6694e48  003c 0073 0076 0067 0020 0076 0069 0065  <.s.v.g. .v.i.e.
                                          ^ User interrupted operation error in 's -u 0 l?7fffffffffff "<svg viewBox'
0:000> ba r1 000002cd`a6694e48
0:000> g
Breakpoint 1 hit
ucrtbase!memcpy+0x2fa:
00007ffb`d9dede1a c5f877          vzeroupper
0:000> k
 # Child-SP          RetAddr               Call Site
00 000000e3`c8d10268 00007ffb`dc700c80     ucrtbase!memcpy+0x2fa
01 000000e3`c8d10270 00007ffa`fd794acc     oleaut32!SysAllocStringLen+0x80
02 000000e3`c8d102a0 00007ffa`fd79342a     msosvg!Mso::SVG::SVGImage::LoadXMLRepresentation+0x3dc
03 000000e3`c8d13370 00007ffa`fd796586     msosvg!Mso::SVG::SVGImage::SVGImage+0xb6
04 000000e3`c8d133b0 00007ffa`fd88e48e     msosvg!Mso::SVG::SVGImage::HasFilters+0x296
05 000000e3`c8d13440 00007ffb`1546eb30     msosvg!Mso::SVG::CreateSVGImage+0xe
06 000000e3`c8d13470 00007ffb`1546eb05     oart!Art::SVGImageCreator::Create+0x1c
07 000000e3`c8d134a0 00007ffb`1546eae7     oart!Art::CreateObjectWithSEH<Art::SVGImageCreator>+0x9
08 000000e3`c8d134d0 00007ffb`152179a7     oart!Art::CreateSVGImage+0x27
09 000000e3`c8d13520 00007ffb`152178b5     oart!Art::Blip::GetSVGImageInternal+0xd7
0a 000000e3`c8d13570 00007ffb`0aa7aa0c     oart!Art::Blip::GetSVGImage+0x35
0b 000000e3`c8d135b0 00007ffb`0a92e1f5     wwlib!Art::Blip::GetSVGImage+0x18
0c 000000e3`c8d135f0 00007ffb`0a2aa6c0     wwlib!GetSizeOfSVGPictureE2o+0x109
0d 000000e3`c8d138a0 00007ffb`09c3b33a     wwlib!WPMGraphicState::WPMGraphicFallBackInfo::ArtoSupportedForMonolithWPM+0x152
0e 000000e3`c8d13a20 00007ffb`0a16a6ef     wwlib!BinaryE2oMonolithController::NotifyArtoChanged+0xea
0f 000000e3`c8d13ab0 00007ffb`0a162ab9     wwlib!PSVECAII::RunInval+0xa7
10 000000e3`c8d13b60 00007ffb`0a1623aa     wwlib!ATSD::RunCmdPostTasks+0x1e9
11 000000e3`c8d13c70 00007ffb`0b3feeaa     wwlib!ATSD::RunCmd+0x27c
12 000000e3`c8d14240 00007ffb`0a6c6b0e     wwlib!FPasteOartFromClipToScrap+0x1d5
13 000000e3`c8d159d0 00007ffb`0a5b61b2     wwlib!FEmbedFileContents+0xe72
14 000000e3`c8d1a360 00007ffb`0a5b3ed0     wwlib!DragDrop::PasteFromData+0x9ba
15 000000e3`c8d1e2e0 00007ffb`dc8761c8     wwlib!DragDrop::DropCore+0x28c
16 000000e3`c8d1e360 00007ffb`dcad36b3     ole32!CPrivDragDrop::PrivDragDrop+0xe8 [com\ole32\com\rot\getif.cxx @ 797]
17 000000e3`c8d1e3b0 00007ffb`dcad570e     RPCRT4!Invoke+0x73
18 000000e3`c8d1e450 00007ffb`dca16c50     RPCRT4!Ndr64StubWorker+0x6ee
19 000000e3`c8d1ea60 00007ffb`dba60bfd     RPCRT4!NdrStubCall3+0xc0
1a 000000e3`c8d1ead0 00007ffb`dba60b3b     combase!CStdStubBuffer_Invoke+0x7d [onecore\com\combase\ndr\ndrole\stub.cxx @ 1413]
1b (Inline Function) --------`--------     combase!InvokeStubWithExceptionPolicyAndTracing::__l6::<lambda_c9f3956a20c9da92a64affc24fdd69ec>::operator()+0x26 [onecore\com\combase\dcomrem\channelb.cxx @ 1152]
1c 000000e3`c8d1eb10 00007ffb`dba600b6     combase!ObjectMethodExceptionHandlingAction<<lambda_c9f3956a20c9da92a64affc24fdd69ec> >+0x47 [onecore\com\combase\dcomrem\excepn.hxx @ 94]
1d (Inline Function) --------`--------     combase!InvokeStubWithExceptionPolicyAndTracing+0x182 [onecore\com\combase\dcomrem\channelb.cxx @ 1150]
1e 000000e3`c8d1eb70 00007ffb`dba5f3c8     combase!DefaultStubInvoke+0x376 [onecore\com\combase\dcomrem\channelb.cxx @ 1219]
1f (Inline Function) --------`--------     combase!SyncStubCall::Invoke+0x7 [onecore\com\combase\dcomrem\channelb.cxx @ 1276]
20 (Inline Function) --------`--------     combase!SyncServerCall::StubInvoke+0x33 [onecore\com\combase\dcomrem\ServerCall.hpp @ 790]
21 000000e3`c8d1ed30 00007ffb`dbad919f     combase!StubInvoke+0x138 [onecore\com\combase\dcomrem\channelb.cxx @ 1485]
22 000000e3`c8d1ee00 00007ffb`dba11744     combase!ServerCall::ContextInvoke+0x28f [onecore\com\combase\dcomrem\ctxchnl.cxx @ 1436]
23 (Inline Function) --------`--------     combase!DefaultInvokeInApartment+0x7c [onecore\com\combase\dcomrem\callctrl.cxx @ 3245]
24 000000e3`c8d1f090 00007ffb`dba2ac4e     combase!ReentrantSTAInvokeInApartment+0x194 [onecore\com\combase\dcomrem\reentrantsta.cpp @ 110]
25 000000e3`c8d1f180 00007ffb`dba1385f     combase!ComInvokeWithLockAndIPID+0xcce [onecore\com\combase\dcomrem\channelb.cxx @ 2152]
26 000000e3`c8d1f480 00007ffb`dbb5d067     combase!ThreadDispatch+0x3ef [onecore\com\combase\dcomrem\channelb.cxx @ 1634]
27 000000e3`c8d1f600 00007ffb`dcd1c396     combase!ThreadWndProc+0x177 [onecore\com\combase\dcomrem\chancont.cxx @ 685]
28 000000e3`c8d1f660 00007ffb`dcd1a7ed     USER32!UserCallWinProcCheckWow+0x356
29 000000e3`c8d1f7c0 00007ffb`09745419     USER32!DispatchMessageWorker+0x1dd
2a 000000e3`c8d1f840 00007ffb`09eb738b     wwlib!MsgPump::FMainLoop+0x5d9
2b 000000e3`c8d1f960 00007ff6`88741f7e     wwlib!FMain+0x7b
2c 000000e3`c8d1f990 00007ff6`88741c76     winword!WinMain+0x28e
2d 000000e3`c8d1fc40 00007ffb`dbe7e8d7     winword!_imp_load_?MsoShouldTraceLoggingMsoYA_NKW4Category+0x20b
2e 000000e3`c8d1fc80 00007ffb`dd36c3fc     KERNEL32!BaseThreadInitThunk+0x17
2f 000000e3`c8d1fcb0 00000000`00000000     ntdll!RtlUserThreadStart+0x2c
0:000> u msosvg!Mso::SVG::CreateSVGImage
Matched: 00007ffa`fd88e4a0 msosvg!Mso::SVG::CreateSVGImage (class Mso::TCntPtr<struct Mso::SVG::ISVGImage> __cdecl Mso::SVG::CreateSVGImage(struct ARC::ICommandList const &,struct GEL::Rect const *))
Matched: 00007ffa`fd88e460 msosvg!Mso::SVG::CreateSVGImage (class Mso::TCntPtr<struct Mso::SVG::ISVGImage> __cdecl Mso::SVG::CreateSVGImage(struct IStream &))
Matched: 00007ffa`fd88e590 msosvg!Mso::SVG::CreateSVGImage (class Mso::TCntPtr<struct Mso::SVG::ISVGImage> __cdecl Mso::SVG::CreateSVGImage(struct ARC::ICommandList const &,struct GEL::Rect const *,struct Mso::SVG::SVGCreationParams const &))
Matched: 00007ffa`fd88e480 msosvg!Mso::SVG::CreateSVGImage (class Mso::TCntPtr<struct Mso::SVG::ISVGImage> __cdecl Mso::SVG::CreateSVGImage(struct IStream &,bool))
Matched: 00007ffa`fd88e5b0 msosvg!Mso::SVG::CreateSVGImage (class Mso::TCntPtr<struct Mso::SVG::ISVGImage> __cdecl Mso::SVG::CreateSVGImage(struct ARC::ICommandList const &,struct GEL::Rect const *,struct Math::TVector2<class Math::TUnits<float,struct Math::TUnitsRatioTag<struct Math::DevicePixels,struct Math::Inches> > > const &))
Ambiguous symbol error at 'msosvg!Mso::SVG::CreateSVGImage'
0:000> u 00007ffa`fd88e48e
msosvg!Mso::SVG::CreateSVGImage+0xe:
00007ffa`fd88e48e 488bc3          mov     rax,rbx
00007ffa`fd88e491 4883c420        add     rsp,20h
00007ffa`fd88e495 5b              pop     rbx
00007ffa`fd88e496 c3              ret
00007ffa`fd88e497 90              nop
00007ffa`fd88e498 90              nop
00007ffa`fd88e499 90              nop
00007ffa`fd88e49a 90              nop
0:000> u 00007ffa`fd88e48e-0xe
msosvg!Mso::SVG::CreateSVGImage:
00007ffa`fd88e480 4053            push    rbx
00007ffa`fd88e482 4883ec20        sub     rsp,20h
00007ffa`fd88e486 488bd9          mov     rbx,rcx
00007ffa`fd88e489 e8aa80f0ff      call    msosvg!Mso::SVG::SVGImage::HasFilters+0x248 (00007ffa`fd796538)
00007ffa`fd88e48e 488bc3          mov     rax,rbx
00007ffa`fd88e491 4883c420        add     rsp,20h
00007ffa`fd88e495 5b              pop     rbx
00007ffa`fd88e496 c3              ret
```

which seems quite sus...

In the ghidra decompilation it looks like this here:

```
undefined8 * __thiscall
Mso::SVG::SVGImageFactory::CreateSVGImage
          (SVGImageFactory *this,undefined8 *param_1,IStream *param_2)

{
  FUN_180006538(param_1,param_2,(bool)this[0x10]);
  return param_1;
}
```

and then here:

```undefined8 * maybe_parse_svg_entrypoint(undefined8 *param_1,IStream *param_2,bool param_3)

{
  SVGImage *this;
  undefined8 *puVar1;

  this = (SVGImage *)Ordinal_52497(0xa0,0);
  if (this == (SVGImage *)0x0) {
    this = (SVGImage *)Ordinal_59938();
  }
  puVar1 = (undefined8 *)Mso::SVG::SVGImage::SVGImage(this,param_2,param_3);
  *param_1 = puVar1;
  if (puVar1 != (undefined8 *)0x0) {
    (**(code **)*puVar1)(puVar1);
  }
  return param_1;
}
```

so the thing is the "stream object"...

then there is this stuff here:

```

/* WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall */
/* public: __cdecl Mso::SVG::SVGImage::SVGImage(struct IStream & __ptr64,bool) __ptr64 */

SVGImage * __thiscall Mso::SVG::SVGImage::SVGImage(SVGImage *this,IStream *param_1,bool param_2)

{
  BSTR bstrString;
  undefined8 *puVar1;
  BSTR local_res10;
  wchar_t *local_res20;

  *(undefined4 *)(this + 8) = 0;
  *(undefined ***)this = &`vftable'{for_`Mso::TRefCountedImpl<struct_Mso::SVG::ISVGImage>'};
  *(undefined ***)(this + 0x10) = &`vftable'{for_`Cache::IResourceState'};
  *(undefined ***)(this + 0x18) = &`vftable'{for_`ICacheResourceStateProvider'};
  *(undefined8 *)(this + 0x20) = 0;
  *(undefined4 *)(this + 0x28) = 0;
  *(undefined8 *)(this + 0x30) = 0;
  *(undefined8 *)(this + 0x38) = 0;
  *(undefined8 *)(this + 0x40) = 0;
  *(undefined8 *)(this + 0x48) = 0;
  *(undefined8 *)(this + 0x50) = 0;
  *(undefined8 *)(this + 0x58) = 0;
  *(undefined8 *)(this + 0x60) = 0;
  *(undefined8 *)(this + 0x68) = 0;
  *(undefined8 *)(this + 0x70) = 0;
  *(undefined8 *)(this + 0x78) = 0;
  _Mtx_init_in_situ(this + 0x30,0x102);
  *(undefined8 *)(this + 0x80) = 0;
  this[0x88] = (SVGImage)0x0;
  *(IStream **)(this + 0x90) = param_1;
  if (param_1 != (IStream *)0x0) {
    (**(code **)(*(longlong *)param_1 + 8))(param_1);
  }
  *(undefined2 *)(this + 0x98) = 0;
  puVar1 = (undefined8 *)LoadXMLRepresentation(&local_res10,*(undefined8 *)(this + 0x90));
  local_res20 = (wchar_t *)*puVar1;
  Init(this,&local_res20,param_2);
  bstrString = local_res10;
  if (local_res10 != (BSTR)0x0) {
    local_res10 = (BSTR)0x0;
    SysFreeString(bstrString);
  }
  return this;
}


```

so now I am wondering where we should put the breakpoint to get the snapshot. Maybe before the LoadXMLRepresentation function???

Here is the XML loading function:

```


/* WARNING: Function: __chkstk replaced with injection: alloca_probe */
/* WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall */
/* public: static class Mso::BStrHolder __cdecl Mso::SVG::SVGImage::LoadXMLRepresentation(struct
   IStream & __ptr64) */

void __cdecl Mso::SVG::SVGImage::LoadXMLRepresentation(undefined8 *param_1,longlong *param_2)

{
  BSTR bstrString;
  code *pcVar1;
  longlong lVar2;
  undefined8 *puVar3;
  long lVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  DWORD DVar8;
  long extraout_EAX;
  byte *pbVar9;
  int *piVar10;
  BSTR pOVar11;
  OLECHAR ****ppppOVar12;
  ulonglong uVar13;
  ulonglong uVar14;
  byte *_Size;
  ulonglong uVar15;
  int iVar16;
  int iVar17;
  uint uVar18;
  bool bVar19;
  bool bVar20;
  undefined auStackY_30c8 [32];
  uint local_3098;
  int local_3094;
  undefined4 local_3090;
  longlong *local_3088;
  undefined8 *local_3080;
  undefined8 *local_3078;
  OLECHAR ***local_3070;
  undefined8 uStack_3068;
  ulonglong local_3060;
  ulonglong local_3058;
  byte abStack_3049 [4097];
  short local_2048 [4096];
  ulonglong local_48;
  undefined8 uStack_40;

  uStack_40 = 0x180004712;
  local_48 = __security_cookie ^ (ulonglong)auStackY_30c8;
  uVar14 = 0;
  local_3090 = 0;
  local_3088 = param_2;
  local_3080 = param_1;
  local_3078 = param_1;
  lVar4 = (**(code **)(*param_2 + 0x28))(param_2,0,0,0);
  if (lVar4 < 0) {
LAB_180004b99:
    Ofc::CHResultException::ThrowTag(lVar4,0x138d858);
    pcVar1 = (code *)swi(3);
    (*pcVar1)();
    return;
  }
  local_3098 = 0;
  iVar7 = (**(code **)(*param_2 + 0x18))(param_2,abStack_3049 + 1,3,&local_3098);
  if (iVar7 < 0) {
    Ofc::CHResultException::ThrowTag(iVar7,0x138d859);
    pcVar1 = (code *)swi(3);
    (*pcVar1)();
    return;
  }
  if (local_3098 < 3) {
    Ofc::CInvalidParamException::ThrowTag(0x138d85a);
LAB_180004bc1:
    Ordinal_21217(0x1111692,0);
    pcVar1 = (code *)swi(3);
    (*pcVar1)();
    return;
  }
  bVar20 = true;
  iVar7 = 1;
  bVar19 = abStack_3049[1] < 0xef;
  uVar18 = 0;
  if (((abStack_3049[1] != 0xef) || (bVar19 = abStack_3049[2] < 0xbb, abStack_3049[2] != 0xbb)) ||
     (bVar19 = abStack_3049[3] < 0xbf, uVar5 = uVar18, abStack_3049[3] != 0xbf)) {
    uVar5 = -(uint)bVar19 | 1;
  }
  uVar13 = uVar14;
  if (uVar5 != 0) {
    bVar19 = abStack_3049[1] < 0xfe;
    if ((abStack_3049[1] != 0xfe) ||
       (bVar19 = abStack_3049[2] != 0xff, uVar5 = uVar18, abStack_3049[2] != 0xff)) {
      uVar5 = -(uint)bVar19 | 1;
    }
    if (uVar5 == 0) {
      local_3094 = 1;
      goto LAB_180004804;
    }
    bVar19 = abStack_3049[1] != 0xff;
    if ((abStack_3049[1] != 0xff) || (bVar19 = abStack_3049[2] < 0xfe, abStack_3049[2] != 0xfe)) {
      uVar18 = -(uint)bVar19 | 1;
    }
    if (uVar18 == 0) {
      iVar7 = 2;
      local_3094 = 2;
      uVar13 = 0;
      goto LAB_180004804;
    }
    uVar13 = 3;
  }
  local_3094 = 0;
  iVar7 = 0;
LAB_180004804:
  uStack_3068 = 0;
  local_3060 = 0;
  local_3058 = 7;
  local_3070 = (OLECHAR ***)0x0;
  do {
    iVar17 = (int)uVar13;
    iVar6 = (**(code **)(*param_2 + 0x18))
                      (param_2,abStack_3049 + (longlong)iVar17 + 1,0x1000 - iVar17,&local_3098);
    if (iVar6 < 0) {
      Ofc::CHResultException::ThrowTag(iVar6,0x138d85b);
      lVar4 = extraout_EAX;
      goto LAB_180004b99;
    }
    if (local_3098 == 0) break;
    iVar16 = iVar17 + local_3098;
    iVar6 = iVar16;
    if (iVar7 == 0) {
      _Size = abStack_3049 + 1;
      iVar7 = Ordinal_54511(0xfde9,0,_Size,iVar16);
      if ((iVar7 == 0) && (DVar8 = GetLastError(), DVar8 == 0x459)) {
        Ofc::CInvalidParamException::ThrowTag(0x138d857);
        pcVar1 = (code *)swi(3);
        (*pcVar1)();
        return;
      }
      if ((1 < iVar7) && (local_2048[(longlong)iVar7 + -1] == -3)) {
        _Size = (byte *)CONCAT71((int7)((ulonglong)_Size >> 8),0xc0);
        for (pbVar9 = abStack_3049 + iVar16; (*pbVar9 & 0xc0) == 0x80; pbVar9 = pbVar9 + -1) {
          iVar16 = iVar16 + -1;
        }
        iVar6 = iVar16 + -1;
        iVar7 = iVar7 + -1;
        if ((abStack_3049[(longlong)(iVar16 + -1) + 1] & 0xc0) != 0xc0) {
          iVar6 = iVar16;
        }
      }
    }
    else if (iVar7 == 1) {
      iVar7 = iVar16 / 2;
      if (0x1000 < iVar7) {
        iVar7 = 0x1000;
      }
      _Size = (byte *)(longlong)(iVar7 * 2);
      pbVar9 = (byte *)(longlong)iVar16;
      if (_Size != (byte *)0x0) {
        if (pbVar9 < _Size) {
          memset(local_2048,0,(size_t)pbVar9);
          piVar10 = _errno();
          *piVar10 = 0x22;
          _invalid_parameter_noinfo();
          _Size = pbVar9;
        }
        else {
          memcpy(local_2048,abStack_3049 + 1,(size_t)_Size);
        }
      }
    }
    else {
      if (iVar7 != 2) goto LAB_180004bc1;
      iVar7 = iVar16 / 2;
      if (0x1000 < iVar7) {
        iVar7 = 0x1000;
      }
      _Size = (byte *)(longlong)iVar7;
      uVar13 = uVar14;
      if (0 < iVar7) {
        do {
          local_2048[uVar13] = CONCAT11(abStack_3049[uVar13 * 2 + 1],abStack_3049[uVar13 * 2 + 2]);
          uVar13 = uVar13 + 1;
        } while ((longlong)uVar13 < (longlong)_Size);
      }
    }
    uVar13 = local_3060;
    if (iVar7 == 0) {
      Ofc::CInvalidParamException::ThrowTag(0x138d85c);
      pcVar1 = (code *)swi(3);
      (*pcVar1)();
      return;
    }
    uVar15 = (ulonglong)iVar7;
    if (local_3058 - local_3060 < uVar15) {
      std::basic_string<>::_Reallocate_grow_by<>
                ((basic_string<> *)&local_3070,uVar15,_Size,local_2048,uVar15);
    }
    else {
      ppppOVar12 = &local_3070;
      if (7 < local_3058) {
        ppppOVar12 = (OLECHAR ****)local_3070;
      }
      lVar2 = local_3060 * 2;
      local_3060 = uVar15 + local_3060;
      memmove((void *)((longlong)ppppOVar12 + lVar2),local_2048,uVar15 * 2);
      *(undefined2 *)((longlong)ppppOVar12 + (uVar15 + uVar13) * 2) = 0;
    }
    if ((0x1000U - (longlong)iVar17 <= (ulonglong)local_3098) ||
       (bVar19 = true, iVar6 != iVar17 + local_3098)) {
      bVar19 = false;
    }
    uVar13 = uVar14;
    if (iVar6 < (int)(iVar17 + local_3098)) {
      uVar18 = iVar17 + (local_3098 - iVar6);
      memmove(abStack_3049 + 1,abStack_3049 + (longlong)iVar6 + 1,(longlong)(int)uVar18);
      uVar13 = (ulonglong)uVar18;
    }
    param_2 = local_3088;
    iVar7 = local_3094;
  } while (!bVar19);
  puVar3 = local_3080;
  *local_3080 = 0;
  local_3090 = 1;
  ppppOVar12 = &local_3070;
  if (7 < local_3058) {
    ppppOVar12 = (OLECHAR ****)local_3070;
  }
  uVar14 = -(ulonglong)(ppppOVar12 != (OLECHAR ****)0x0) & local_3060;
  if (ppppOVar12 != (OLECHAR ****)0x0) {
    if (0xffffffff < uVar14) {
      safeint_exception_handlers::SafeInt_InvalidParameter::SafeIntOnOverflow();
      pcVar1 = (code *)swi(3);
      (*pcVar1)();
      return;
    }
    pOVar11 = SysAllocStringLen((OLECHAR *)ppppOVar12,(UINT)uVar14);
    bstrString = (BSTR)*puVar3;
    if (bstrString != (BSTR)0x0) {
      *puVar3 = 0;
      SysFreeString(bstrString);
    }
    *puVar3 = pOVar11;
    bVar20 = pOVar11 != (BSTR)0x0;
  }
  if (!bVar20) {
    Ofc::CHResultException::ThrowTag(~-(uint)bVar20 & 0x8007000e,0x138d85d);
    pcVar1 = (code *)swi(3);
    (*pcVar1)();
    return;
  }
  if (7 < local_3058) {
    ppppOVar12 = (OLECHAR ****)local_3070;
    if ((0xfff < local_3058 * 2 + 2) &&
       (ppppOVar12 = (OLECHAR ****)local_3070[-1],
       0x1f < (ulonglong)((longlong)local_3070 + (-8 - (longlong)ppppOVar12)))) {
                    /* WARNING: Subroutine does not return */
      _invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    }
    free(ppppOVar12);
  }
  __security_check_cookie(local_48 ^ (ulonglong)auStackY_30c8);
  return;
}


```

Now, one way would be to use the thing in IStream and patch those in our fuzzing harness:

Definitions of an IStream object taken from the thing:

```

#ifndef __IStream_INTERFACE_DEFINED__
#define __IStream_INTERFACE_DEFINED__

/* interface IStream */
/* [unique][uuid][object] */

typedef /* [unique] */  __RPC_unique_pointer IStream *LPSTREAM;

typedef struct tagSTATSTG
    {
    LPOLESTR pwcsName;
    DWORD type;
    ULARGE_INTEGER cbSize;
    FILETIME mtime;
    FILETIME ctime;
    FILETIME atime;
    DWORD grfMode;
    DWORD grfLocksSupported;
    CLSID clsid;
    DWORD grfStateBits;
    DWORD reserved;
    } 	STATSTG;

typedef
enum tagSTGTY
    {
        STGTY_STORAGE	= 1,
        STGTY_STREAM	= 2,
        STGTY_LOCKBYTES	= 3,
        STGTY_PROPERTY	= 4
    } 	STGTY;

typedef
enum tagSTREAM_SEEK
    {
        STREAM_SEEK_SET	= 0,
        STREAM_SEEK_CUR	= 1,
        STREAM_SEEK_END	= 2
    } 	STREAM_SEEK;

typedef
enum tagLOCKTYPE
    {
        LOCK_WRITE	= 1,
        LOCK_EXCLUSIVE	= 2,
        LOCK_ONLYONCE	= 4
    } 	LOCKTYPE;


EXTERN_C const IID IID_IStream;

#if defined(__cplusplus) && !defined(CINTERFACE)

    MIDL_INTERFACE("0000000c-0000-0000-C000-000000000046")
    IStream : public ISequentialStream
    {
    public:
        virtual /* [local] */ HRESULT STDMETHODCALLTYPE Seek(
            /* [in] */ LARGE_INTEGER dlibMove,
            /* [in] */ DWORD dwOrigin,
            /* [annotation] */
            _Out_opt_  ULARGE_INTEGER *plibNewPosition) = 0;

        virtual HRESULT STDMETHODCALLTYPE SetSize(
            /* [in] */ ULARGE_INTEGER libNewSize) = 0;

        virtual /* [local] */ HRESULT STDMETHODCALLTYPE CopyTo(
            /* [annotation][unique][in] */
            _In_  IStream *pstm,
            /* [in] */ ULARGE_INTEGER cb,
            /* [annotation] */
            _Out_opt_  ULARGE_INTEGER *pcbRead,
            /* [annotation] */
            _Out_opt_  ULARGE_INTEGER *pcbWritten) = 0;

        virtual HRESULT STDMETHODCALLTYPE Commit(
            /* [in] */ DWORD grfCommitFlags) = 0;

        virtual HRESULT STDMETHODCALLTYPE Revert( void) = 0;

        virtual HRESULT STDMETHODCALLTYPE LockRegion(
            /* [in] */ ULARGE_INTEGER libOffset,
            /* [in] */ ULARGE_INTEGER cb,
            /* [in] */ DWORD dwLockType) = 0;

        virtual HRESULT STDMETHODCALLTYPE UnlockRegion(
            /* [in] */ ULARGE_INTEGER libOffset,
            /* [in] */ ULARGE_INTEGER cb,
            /* [in] */ DWORD dwLockType) = 0;

        virtual HRESULT STDMETHODCALLTYPE Stat(
            /* [out] */ __RPC__out STATSTG *pstatstg,
            /* [in] */ DWORD grfStatFlag) = 0;

        virtual HRESULT STDMETHODCALLTYPE Clone(
            /* [out] */ __RPC__deref_out_opt IStream **ppstm) = 0;

    };


#else 	/* C style interface */

    typedef struct IStreamVtbl
    {
        BEGIN_INTERFACE

        HRESULT ( STDMETHODCALLTYPE *QueryInterface )(
            __RPC__in IStream * This,
            /* [in] */ __RPC__in REFIID riid,
            /* [annotation][iid_is][out] */
            _COM_Outptr_  void **ppvObject);

        ULONG ( STDMETHODCALLTYPE *AddRef )(
            __RPC__in IStream * This);

        ULONG ( STDMETHODCALLTYPE *Release )(
            __RPC__in IStream * This);

        /* [local] */ HRESULT ( STDMETHODCALLTYPE *Read )(
            IStream * This,
            /* [annotation] */
            _Out_writes_bytes_to_(cb, *pcbRead)  void *pv,
            /* [annotation][in] */
            _In_  ULONG cb,
            /* [annotation] */
            _Out_opt_  ULONG *pcbRead);

        /* [local] */ HRESULT ( STDMETHODCALLTYPE *Write )(
            IStream * This,
            /* [annotation] */
            _In_reads_bytes_(cb)  const void *pv,
            /* [annotation][in] */
            _In_  ULONG cb,
            /* [annotation] */
            _Out_opt_  ULONG *pcbWritten);

        /* [local] */ HRESULT ( STDMETHODCALLTYPE *Seek )(
            IStream * This,
            /* [in] */ LARGE_INTEGER dlibMove,
            /* [in] */ DWORD dwOrigin,
            /* [annotation] */
            _Out_opt_  ULARGE_INTEGER *plibNewPosition);

        HRESULT ( STDMETHODCALLTYPE *SetSize )(
            __RPC__in IStream * This,
            /* [in] */ ULARGE_INTEGER libNewSize);

        /* [local] */ HRESULT ( STDMETHODCALLTYPE *CopyTo )(
            IStream * This,
            /* [annotation][unique][in] */
            _In_  IStream *pstm,
            /* [in] */ ULARGE_INTEGER cb,
            /* [annotation] */
            _Out_opt_  ULARGE_INTEGER *pcbRead,
            /* [annotation] */
            _Out_opt_  ULARGE_INTEGER *pcbWritten);

        HRESULT ( STDMETHODCALLTYPE *Commit )(
            __RPC__in IStream * This,
            /* [in] */ DWORD grfCommitFlags);

        HRESULT ( STDMETHODCALLTYPE *Revert )(
            __RPC__in IStream * This);

        HRESULT ( STDMETHODCALLTYPE *LockRegion )(
            __RPC__in IStream * This,
            /* [in] */ ULARGE_INTEGER libOffset,
            /* [in] */ ULARGE_INTEGER cb,
            /* [in] */ DWORD dwLockType);

        HRESULT ( STDMETHODCALLTYPE *UnlockRegion )(
            __RPC__in IStream * This,
            /* [in] */ ULARGE_INTEGER libOffset,
            /* [in] */ ULARGE_INTEGER cb,
            /* [in] */ DWORD dwLockType);

        HRESULT ( STDMETHODCALLTYPE *Stat )(
            __RPC__in IStream * This,
            /* [out] */ __RPC__out STATSTG *pstatstg,
            /* [in] */ DWORD grfStatFlag);

        HRESULT ( STDMETHODCALLTYPE *Clone )(
            __RPC__in IStream * This,
            /* [out] */ __RPC__deref_out_opt IStream **ppstm);

        END_INTERFACE
    } IStreamVtbl;

    interface IStream
    {
        CONST_VTBL struct IStreamVtbl *lpVtbl;
    };



#ifdef COBJMACROS


#define IStream_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) )

#define IStream_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) )

#define IStream_Release(This)	\
    ( (This)->lpVtbl -> Release(This) )


#define IStream_Read(This,pv,cb,pcbRead)	\
    ( (This)->lpVtbl -> Read(This,pv,cb,pcbRead) )

#define IStream_Write(This,pv,cb,pcbWritten)	\
    ( (This)->lpVtbl -> Write(This,pv,cb,pcbWritten) )


#define IStream_Seek(This,dlibMove,dwOrigin,plibNewPosition)	\
    ( (This)->lpVtbl -> Seek(This,dlibMove,dwOrigin,plibNewPosition) )

#define IStream_SetSize(This,libNewSize)	\
    ( (This)->lpVtbl -> SetSize(This,libNewSize) )

#define IStream_CopyTo(This,pstm,cb,pcbRead,pcbWritten)	\
    ( (This)->lpVtbl -> CopyTo(This,pstm,cb,pcbRead,pcbWritten) )

#define IStream_Commit(This,grfCommitFlags)	\
    ( (This)->lpVtbl -> Commit(This,grfCommitFlags) )

#define IStream_Revert(This)	\
    ( (This)->lpVtbl -> Revert(This) )

#define IStream_LockRegion(This,libOffset,cb,dwLockType)	\
    ( (This)->lpVtbl -> LockRegion(This,libOffset,cb,dwLockType) )

#define IStream_UnlockRegion(This,libOffset,cb,dwLockType)	\
    ( (This)->lpVtbl -> UnlockRegion(This,libOffset,cb,dwLockType) )

#define IStream_Stat(This,pstatstg,grfStatFlag)	\
    ( (This)->lpVtbl -> Stat(This,pstatstg,grfStatFlag) )

#define IStream_Clone(This,ppstm)	\
    ( (This)->lpVtbl -> Clone(This,ppstm) )

#endif /* COBJMACROS */


#endif 	/* C style interface */



/* [call_as] */ HRESULT STDMETHODCALLTYPE IStream_RemoteSeek_Proxy(
    __RPC__in IStream * This,
    /* [in] */ LARGE_INTEGER dlibMove,
    /* [in] */ DWORD dwOrigin,
    /* [out] */ __RPC__out ULARGE_INTEGER *plibNewPosition);


void __RPC_STUB IStream_RemoteSeek_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);


/* [call_as] */ HRESULT STDMETHODCALLTYPE IStream_RemoteCopyTo_Proxy(
    __RPC__in IStream * This,
    /* [unique][in] */ __RPC__in_opt IStream *pstm,
    /* [in] */ ULARGE_INTEGER cb,
    /* [out] */ __RPC__out ULARGE_INTEGER *pcbRead,
    /* [out] */ __RPC__out ULARGE_INTEGER *pcbWritten);


void __RPC_STUB IStream_RemoteCopyTo_Stub(
    IRpcStubBuffer *This,
    IRpcChannelBuffer *_pRpcChannelBuffer,
    PRPC_MESSAGE _pRpcMessage,
    DWORD *_pdwStubPhase);



#endif 	/* __IStream_INTERFACE_DEFINED__ */
```

windows 10 sdk...



It seems that the SVG parsing is done in two functions, which makes this a lot trickier... First of all, the actual xml parsing is done by that function, but then the parsing of the actual effects is done by the AcquireEffectTree function, therefore this makes it a lot trickier to fuzz effectively...

Here is the stuff:

```
0:000> dq rdx
000002cd`9cbd3fc0  00007ffb`093f73f0 00007ffb`093f73b0
000002cd`9cbd3fd0  00007ffb`093f7390 00000000`00000000
000002cd`9cbd3fe0  00000000`00000000 00000000`00000000
000002cd`9cbd3ff0  00000000`00000007 d0d0d0d0`d0d0d0d0
000002cd`9cbd4000  ????????`???????? ????????`????????
000002cd`9cbd4010  ????????`???????? ????????`????????
000002cd`9cbd4020  ????????`???????? ????????`????????
000002cd`9cbd4030  ????????`???????? ????????`????????
0:000> dq poi(rdx)
00007ffb`093f73f0  00007ffb`08e35dc0 00007ffb`08de7960
00007ffb`093f7400  00007ffb`08de7cd0 00007ffb`08de7d20
00007ffb`093f7410  00007ffb`08e3a0d0 00007ffb`08de7e40
00007ffb`093f7420  00007ffb`08e38eb0 00007ffb`08eb85f0
00007ffb`093f7430  00007ffb`08e962f0 00007ffb`092d6090
00007ffb`093f7440  00007ffb`092d5ff0 00007ffb`092d60d0
00007ffb`093f7450  00007ffb`08de7640 00007ffb`092d5ee0
00007ffb`093f7460  77073096`00000000 990951ba`ee0e612c
0:000> uf 00007ffb`08de7d20
mso20win32client!CByteStreamToIStream::Read:
00007ffb`08de7d20 488bc4          mov     rax,rsp
00007ffb`08de7d23 48895808        mov     qword ptr [rax+8],rbx
00007ffb`08de7d27 48896818        mov     qword ptr [rax+18h],rbp
00007ffb`08de7d2b 48897020        mov     qword ptr [rax+20h],rsi
00007ffb`08de7d2f 57              push    rdi
00007ffb`08de7d30 4883ec40        sub     rsp,40h
00007ffb`08de7d34 c7401000000000  mov     dword ptr [rax+10h],0
00007ffb`08de7d3b 498bf9          mov     rdi,r9
00007ffb`08de7d3e 418bf0          mov     esi,r8d
00007ffb`08de7d41 488bea          mov     rbp,rdx
00007ffb`08de7d44 488bd9          mov     rbx,rcx
00007ffb`08de7d47 4885d2          test    rdx,rdx
00007ffb`08de7d4a 0f84d2000000    je      mso20win32client!CByteStreamToIStream::Read+0x102 (00007ffb`08de7e22)  Branch

mso20win32client!CByteStreamToIStream::Read+0x30:
00007ffb`08de7d50 33c9            xor     ecx,ecx
00007ffb`08de7d52 4585c0          test    r8d,r8d
00007ffb`08de7d55 7475            je      mso20win32client!CByteStreamToIStream::Read+0xac (00007ffb`08de7dcc)  Branch

mso20win32client!CByteStreamToIStream::Read+0x37:
00007ffb`08de7d57 394bf0          cmp     dword ptr [rbx-10h],ecx
00007ffb`08de7d5a 0f85a2000000    jne     mso20win32client!CByteStreamToIStream::Read+0xe2 (00007ffb`08de7e02)  Branch

mso20win32client!CByteStreamToIStream::Read+0x40:
00007ffb`08de7d60 488d4ba0        lea     rcx,[rbx-60h]
00007ffb`08de7d64 4883793000      cmp     qword ptr [rcx+30h],0
00007ffb`08de7d69 0f8481000000    je      mso20win32client!CByteStreamToIStream::Read+0xd0 (00007ffb`08de7df0)  Branch

mso20win32client!CByteStreamToIStream::Read+0x4f:
00007ffb`08de7d6f ba01000000      mov     edx,1
00007ffb`08de7d74 e887cb0400      call    mso20win32client!CByteStreamWrapperBase::FContinueInternalCore (00007ffb`08e34900)

mso20win32client!CByteStreamToIStream::Read+0x59:
00007ffb`08de7d79 85c0            test    eax,eax
00007ffb`08de7d7b 0f84a8000000    je      mso20win32client!CByteStreamToIStream::Read+0x109 (00007ffb`08de7e29)  Branch

mso20win32client!CByteStreamToIStream::Read+0x61:
00007ffb`08de7d81 488d4bc8        lea     rcx,[rbx-38h]
00007ffb`08de7d85 e8eecb2000      call    mso20win32client!Mso::TCntPtr<Mso::Logging::IThrottlingConfiguration const >::operator-> (00007ffb`08ff4978)
00007ffb`08de7d8a 488b53e0        mov     rdx,qword ptr [rbx-20h]
00007ffb`08de7d8e 4c8d050b030000  lea     r8,[mso20win32client!CFileByteStreamSimple::ReadAt (00007ffb`08de80a0)]
00007ffb`08de7d95 448bce          mov     r9d,esi
00007ffb`08de7d98 488b08          mov     rcx,qword ptr [rax]
00007ffb`08de7d9b 4c8b5118        mov     r10,qword ptr [rcx+18h]
00007ffb`08de7d9f 488b4bd8        mov     rcx,qword ptr [rbx-28h]
00007ffb`08de7da3 4d3bd0          cmp     r10,r8
00007ffb`08de7da6 48894c2428      mov     qword ptr [rsp+28h],rcx
00007ffb`08de7dab 4c8bc5          mov     r8,rbp
00007ffb`08de7dae 488d4c2458      lea     rcx,[rsp+58h]
00007ffb`08de7db3 48894c2420      mov     qword ptr [rsp+20h],rcx
00007ffb`08de7db8 488bc8          mov     rcx,rax
00007ffb`08de7dbb 753a            jne     mso20win32client!CByteStreamToIStream::Read+0xd7 (00007ffb`08de7df7)  Branch

mso20win32client!CByteStreamToIStream::Read+0x9d:
00007ffb`08de7dbd e8de020000      call    mso20win32client!CFileByteStreamSimple::ReadAt (00007ffb`08de80a0)

mso20win32client!CByteStreamToIStream::Read+0xa2:
00007ffb`08de7dc2 8bc8            mov     ecx,eax
00007ffb`08de7dc4 8b442458        mov     eax,dword ptr [rsp+58h]
00007ffb`08de7dc8 480143e0        add     qword ptr [rbx-20h],rax

mso20win32client!CByteStreamToIStream::Read+0xac:
00007ffb`08de7dcc 4885ff          test    rdi,rdi
00007ffb`08de7dcf 7406            je      mso20win32client!CByteStreamToIStream::Read+0xb7 (00007ffb`08de7dd7)  Branch

mso20win32client!CByteStreamToIStream::Read+0xb1:
00007ffb`08de7dd1 8b442458        mov     eax,dword ptr [rsp+58h]
00007ffb`08de7dd5 8907            mov     dword ptr [rdi],eax

mso20win32client!CByteStreamToIStream::Read+0xb7:
00007ffb`08de7dd7 488b5c2450      mov     rbx,qword ptr [rsp+50h]
00007ffb`08de7ddc 488b6c2460      mov     rbp,qword ptr [rsp+60h]
00007ffb`08de7de1 488b742468      mov     rsi,qword ptr [rsp+68h]
00007ffb`08de7de6 4883c440        add     rsp,40h
00007ffb`08de7dea 5f              pop     rdi
00007ffb`08de7deb e990010000      jmp     mso20win32client!CByteStreamWrapperBase::TranslateErrorCode (00007ffb`08de7f80)  Branch

mso20win32client!CByteStreamToIStream::Read+0xd0:
00007ffb`08de7df0 b801000000      mov     eax,1
00007ffb`08de7df5 eb82            jmp     mso20win32client!CByteStreamToIStream::Read+0x59 (00007ffb`08de7d79)  Branch

mso20win32client!CByteStreamToIStream::Read+0xd7:
00007ffb`08de7df7 498bc2          mov     rax,r10
00007ffb`08de7dfa ff1598546b00    call    qword ptr [mso20win32client!_guard_dispatch_icall_fptr (00007ffb`0949d298)]
00007ffb`08de7e00 ebc0            jmp     mso20win32client!CByteStreamToIStream::Read+0xa2 (00007ffb`08de7dc2)  Branch

mso20win32client!CByteStreamToIStream::Read+0xe2:
00007ffb`08de7e02 ff1530d25300    call    qword ptr [mso20win32client!_imp_GetCurrentThreadId (00007ffb`09325038)]
00007ffb`08de7e08 3943f0          cmp     dword ptr [rbx-10h],eax
00007ffb`08de7e0b 0f844fffffff    je      mso20win32client!CByteStreamToIStream::Read+0x40 (00007ffb`08de7d60)  Branch

mso20win32client!CByteStreamToIStream::Read+0xf1:
00007ffb`08de7e11 b991986c00      mov     ecx,6C9891h
00007ffb`08de7e16 e8d5880d00      call    mso20win32client!MsoShipAssertTagProc (00007ffb`08ec06f0)
00007ffb`08de7e1b b905400080      mov     ecx,80004005h
00007ffb`08de7e20 ebaa            jmp     mso20win32client!CByteStreamToIStream::Read+0xac (00007ffb`08de7dcc)  Branch

mso20win32client!CByteStreamToIStream::Read+0x102:
00007ffb`08de7e22 b903400080      mov     ecx,80004003h
00007ffb`08de7e27 eba3            jmp     mso20win32client!CByteStreamToIStream::Read+0xac (00007ffb`08de7dcc)  Branch

mso20win32client!CByteStreamToIStream::Read+0x109:
00007ffb`08de7e29 b904400080      mov     ecx,80004004h
00007ffb`08de7e2e eb9c            jmp     mso20win32client!CByteStreamToIStream::Read+0xac (00007ffb`08de7dcc)  Branch

mso20win32client!CByteStreamWrapperBase::TranslateErrorCode:
00007ffb`08de7f80 85c9            test    ecx,ecx
00007ffb`08de7f82 7803            js      mso20win32client!CByteStreamWrapperBase::TranslateErrorCode+0x7 (00007ffb`08de7f87)  Branch

mso20win32client!CByteStreamWrapperBase::TranslateErrorCode+0x4:
00007ffb`08de7f84 8bc1            mov     eax,ecx
00007ffb`08de7f86 c3              ret

```

Here:

```
0:000> g
Breakpoint 5 hit
msosvg!Mso::SVG::SVGImage::LoadXMLRepresentation+0x3dc:
00007ffa`fd794acc 488bf8          mov     rdi,rax
0:000> r
rax=000002cda6694e48 rbx=0000000000000000 rcx=000002cda6694f60
rdx=000002cd9fe86fe8 rsi=0000000000000001 rdi=0000000000000001
rip=00007ffafd794acc rsp=000000e3c8d0ba60 rbp=000000e3c8d0bb60
 r8=0000000000000012  r9=0000000000000020 r10=00007ffbd9d00000
r11=00007ffbd9dede0f r12=0000000000000095 r13=0000000000001000
r14=000000e3c8d0eb78 r15=0000000000000000
iopl=0         nv up ei pl nz na pe nc
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
msosvg!Mso::SVG::SVGImage::LoadXMLRepresentation+0x3dc:
00007ffa`fd794acc 488bf8          mov     rdi,rax
0:000> dq 000002cda6694e48
000002cd`a6694e48  00670076`0073003c 00650069`00760020
000002cd`a6694e58  0078006f`00420077 00200030`0027003d
000002cd`a6694e68  00300031`00200030 00330039`00200035
000002cd`a6694e78  006d0078`00200027 003d0073`006e006c
000002cd`a6694e88  00740074`00680027 002f002f`003a0070
000002cd`a6694e98  002e0077`00770077 006f002e`00330077
000002cd`a6694ea8  0032002f`00670072 002f0030`00300030
000002cd`a6694eb8  00270067`00760073 0070003c`000a003e
```

but I think this is bad, because we do not control the length of the allocated stuff??? I need to manipulate the length being allocated no??? Here:

```       180004ac3 49 8b c8        MOV        bstr_stuff_output_maybe,R8
       180004ac6 ff 15 a4        CALL       qword ptr [->OLEAUT32.DLL::SysAllocStringLen]    = 8000000000000004
                 16 14 00
       180004acc 48 8b f8        MOV        RDI,sus_string_stuff
`` here: ```0:000> du 000002cda6694e48
000002cd`a6694e48  "<svg viewBox='0 0 105 93' xmlns="
000002cd`a6694e88  "'http://www.w3.org/2000/svg'>.<p"
000002cd`a6694ec8  "ath d='M66,0h39v93zM38,0h-38v93z"
000002cd`a6694f08  "M52,35l25,58h-16l-8-18h-18z' fil"
000002cd`a6694f48  "l='#ED1C24'/>.</svg>."
```

now, if the svg was larger than x, then we would overflow the buffer. One way to fix this is to just use a big svg file say 20kb or something like that and then just restrict ourselves to that size no? I think that such is the best way to ensure that we do not overflow the buffer magically. Then the next thing which we need to figure out is the address where we need to break the fuzzer. Now, the issue is that the "AcquireEffectTree" function is not called when initializing the svg file, but instead it is called later on. I don't think this is an issue, since we control every part of machine execution no? I think this is the spot where to inject our payload?

Ok, so I think the best strategy is to just break here:

```
    sus_string_stuff = SysAllocStringLen((OLECHAR *)ppppOVar11,(UINT)uVar13);
    bstrString = (BSTR)*puVar3;
```

after the call to the SysAllocStringLen and then we have the thing no?


7ff849930000 69d4ae10 Apr 07 10:11:12 2026 C:\Program Files\Microsoft Office\root\Office16\msosvg.dll



7ff849930000+46f0










00007ff8`a5a20000 00007ff8`a5bdd000   msosvg     (deferred)

and then:

```
00007ff8`a5a24ad7 49891e          mov     qword ptr [r14],rbx
00007ff8`a5a24ada ff1568161400    call    qword ptr [msosvg!_imp_SysFreeString (00007ff8`a5b66148)]
kd> bu 00007ff8`a5a24ac6
kd> bp 00007ff8`a5a24ac6
breakpoint 0 redefined
kd> g
Breakpoint 0 hit
msosvg!Mso::SVG::SVGImage::LoadXMLRepresentation+0x3d6:
0033:00007ff8`a5a24ac6 ff15a4161400    call    qword ptr [msosvg!_imp_SysAllocStringLen (00007ff8`a5b66170)]
kd> u
msosvg!Mso::SVG::SVGImage::LoadXMLRepresentation+0x3d6:
00007ff8`a5a24ac6 ff15a4161400    call    qword ptr [msosvg!_imp_SysAllocStringLen (00007ff8`a5b66170)]
00007ff8`a5a24acc 488bf8          mov     rdi,rax
00007ff8`a5a24acf 498b0e          mov     rcx,qword ptr [r14]
00007ff8`a5a24ad2 4885c9          test    rcx,rcx
00007ff8`a5a24ad5 7409            je      msosvg!Mso::SVG::SVGImage::LoadXMLRepresentation+0x3f0 (00007ff8`a5a24ae0)
00007ff8`a5a24ad7 49891e          mov     qword ptr [r14],rbx
00007ff8`a5a24ada ff1568161400    call    qword ptr [msosvg!_imp_SysFreeString (00007ff8`a5b66148)]
00007ff8`a5a24ae0 49893e          mov     qword ptr [r14],rdi
kd> r
rax=00000000ffffffff rbx=0000000000000000 rcx=0000021076249980
rdx=0000000000019688 rsi=0000000000000001 rdi=0000021076249901
rip=00007ff8a5a24ac6 rsp=0000003931d5f230 rbp=0000003931d5f330
 r8=0000021076249980  r9=000000000002232d r10=00007ff8ada70000
r11=00007ff8ada82345 r12=0000000000000688 r13=0000000000001000
r14=0000003931d62348 r15=0000000000000000
iopl=0         nv up ei ng nz ac pe cy
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000293
msosvg!Mso::SVG::SVGImage::LoadXMLRepresentation+0x3d6:
0033:00007ff8`a5a24ac6 ff15a4161400    call    qword ptr [msosvg!_imp_SysAllocStringLen (00007ff8`a5b66170)] ds:002b:00007ff8`a5b66170={oleaut32!SysAllocStringLen (00007ff8`cc102b50)}

```


then:

```
kd> g
Breakpoint 0 hit
msosvg!Mso::SVG::SVGImage::LoadXMLRepresentation+0x3d6:
0033:00007ff8`a5a24ac6 ff15a4161400    call    qword ptr [msosvg!_imp_SysAllocStringLen (00007ff8`a5b66170)]
kd> u
msosvg!Mso::SVG::SVGImage::LoadXMLRepresentation+0x3d6:
00007ff8`a5a24ac6 ff15a4161400    call    qword ptr [msosvg!_imp_SysAllocStringLen (00007ff8`a5b66170)]
00007ff8`a5a24acc 488bf8          mov     rdi,rax
00007ff8`a5a24acf 498b0e          mov     rcx,qword ptr [r14]
00007ff8`a5a24ad2 4885c9          test    rcx,rcx
00007ff8`a5a24ad5 7409            je      msosvg!Mso::SVG::SVGImage::LoadXMLRepresentation+0x3f0 (00007ff8`a5a24ae0)
00007ff8`a5a24ad7 49891e          mov     qword ptr [r14],rbx
00007ff8`a5a24ada ff1568161400    call    qword ptr [msosvg!_imp_SysFreeString (00007ff8`a5b66148)]
00007ff8`a5a24ae0 49893e          mov     qword ptr [r14],rdi
kd> r
rax=00000000ffffffff rbx=0000000000000000 rcx=0000021076249980
rdx=0000000000019688 rsi=0000000000000001 rdi=0000021076249901
rip=00007ff8a5a24ac6 rsp=0000003931d5f230 rbp=0000003931d5f330
 r8=0000021076249980  r9=000000000002232d r10=00007ff8ada70000
r11=00007ff8ada82345 r12=0000000000000688 r13=0000000000001000
r14=0000003931d62348 r15=0000000000000000
iopl=0         nv up ei ng nz ac pe cy
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000293
msosvg!Mso::SVG::SVGImage::LoadXMLRepresentation+0x3d6:
0033:00007ff8`a5a24ac6 ff15a4161400    call    qword ptr [msosvg!_imp_SysAllocStringLen (00007ff8`a5b66170)] ds:002b:00007ff8`a5b66170={oleaut32!SysAllocStringLen (00007ff8`cc102b50)}
kd> bu 00007ff8`a5a24acc
kd> g
Breakpoint 1 hit
msosvg!Mso::SVG::SVGImage::LoadXMLRepresentation+0x3dc:
0033:00007ff8`a5a24acc 488bf8          mov     rdi,rax
kd> u
msosvg!Mso::SVG::SVGImage::LoadXMLRepresentation+0x3dc:
00007ff8`a5a24acc 488bf8          mov     rdi,rax
00007ff8`a5a24acf 498b0e          mov     rcx,qword ptr [r14]
00007ff8`a5a24ad2 4885c9          test    rcx,rcx
00007ff8`a5a24ad5 7409            je      msosvg!Mso::SVG::SVGImage::LoadXMLRepresentation+0x3f0 (00007ff8`a5a24ae0)
00007ff8`a5a24ad7 49891e          mov     qword ptr [r14],rbx
00007ff8`a5a24ada ff1568161400    call    qword ptr [msosvg!_imp_SysFreeString (00007ff8`a5b66148)]
00007ff8`a5a24ae0 49893e          mov     qword ptr [r14],rdi
00007ff8`a5a24ae3 8bf3            mov     esi,ebx
kd> !load C:\Users\elsku\snapshot\snapshot.dll
kd> !snapshot C:\Users\elsku\state_dump\
[dbgeng-rs] Dumping the CPU state into C:\Users\elsku\state_dump\state.19041.1.amd64fre.vb_release.191206-1406.20260429_0159\regs.json..
[dbgeng-rs] Dumping the memory state into C:\Users\elsku\state_dump\state.19041.1.amd64fre.vb_release.191206-1406.20260429_0159\mem.dmp..
Creating C:\\Users\\elsku\\state_dump\\state.19041.1.amd64fre.vb_release.191206-1406.20260429_0159\\mem.dmp - Full memory range dump
0% written.
5% written. 2 min 47 sec remaining.
10% written. 2 min 43 sec remaining.
15% written. 2 min 32 sec remaining.
20% written. 2 min 24 sec remaining.
25% written. 2 min 14 sec remaining.
30% written. 2 min 3 sec remaining.
35% written. 1 min 52 sec remaining.
40% written. 1 min 45 sec remaining.
45% written. 1 min 38 sec remaining.
50% written. 1 min 31 sec remaining.
55% written. 1 min 17 sec remaining.
60% written. 1 min 7 sec remaining.
65% written. 56 sec remaining.
70% written. 46 sec remaining.
75% written. 39 sec remaining.
80% written. 31 sec remaining.
85% written. 24 sec remaining.
90% written. 18 sec remaining.
95% written. 8 sec remaining.
Wrote 4.0 GB in 2 min 52 sec.
The average transfer rate was 23.5 MB/s.
Dump successfully written
[dbgeng-rs] Done!
```


Ok, so the dump directory "C:\Users\elsku\state_dump5" contains the most important dump that processed the thing the fastest. That I think is the best for fuzzing, since it went on to process the effect tree much quicker than the other ones... It took a couple of seconds to call the AcquireEffectTree function. I think this is decent, but we could do better.

I think that maybe calling the AcquireEffectTree method of the newly created svg object immediately after the XML parsing but then we need to essentially debug what those parameters are and we should be good? The first param1 is just a pointer to a return value or something? Not really certain or is that the effect tree pointer that it is supposed to return??? Could be. Then that param2 is an array of some kind and then the last is something else. The only really interesting function we need to reach is the "RenderRoot" function and we can stop after that. Therefore having a sort of thing to call the effect tree function straight after should be good no?

I think that just trying to get the snapshot based fuzzer to at least somewhat work first should be a good goal. Let's try to spin up something that actually fuzzes that XML parsing at the very least.

Here is the stuff again:

```
45 00000009`9b2ff480 00007ffa`f8594fdc     wwlib!MsgPump::WaitForPostedMessage+0x2b9
46 00000009`9b2ff500 00007ffa`f8d0738b     wwlib!MsgPump::FMainLoop+0x19c
47 00000009`9b2ff620 00007ff6`b3c21f7e     wwlib!FMain+0x7b
48 00000009`9b2ff650 00007ff6`b3c21c76     WINWORD!WinMain+0x28e
49 00000009`9b2ff900 00007ffb`44c97344     WINWORD!_imp_load_?MsoShouldTraceLoggingMsoYA_NKW4Category+0x20b
4a 00000009`9b2ff940 00007ffb`463026b1     KERNEL32!BaseThreadInitThunk+0x14
4b 00000009`9b2ff970 00000000`00000000     ntdll!RtlUserThreadStart+0x21
kd> r
rax=00000000ffffffff rbx=0000000000000000 rcx=000001378bf03980
rdx=00000000000189e1 rsi=0000000000000001 rdi=000001378bf03901
rip=00007ffb1d544ac6 rsp=000000099b2ec5c0 rbp=000000099b2ec6c0
 r8=000001378bf03980  r9=000000000002232d r10=00007ffb26510000
r11=00007ffb2652236d r12=00000000000009e1 r13=0000000000001000
r14=000000099b2ef6d8 r15=0000000000000000
iopl=0         nv up ei ng nz ac pe cy
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000297
msosvg!Mso::SVG::SVGImage::LoadXMLRepresentation+0x3d6:
0033:00007ffb`1d544ac6 ff15a4161400    call    qword ptr [msosvg!_imp_SysAllocStringLen (00007ffb`1d686170)] ds:002b:00007ffb`1d686170={oleaut32!SysAllocStringLen (00007ffb`46002b50)}
kd> ds 000001378bf03980
00640069`00770020  "????????????????????????????????"
00640069`00770040  "????????????????????????????"
kd> du 000001378bf03980
00000137`8bf03980  "<svg width="1000" height="1000" "
00000137`8bf039c0  "xmlns="http://www.w3.org/2000/sv"
00000137`8bf03a00  "g" xmlns:xlink="http://www.w3.or"
00000137`8bf03a40  "g/1999/xlink" overflow="hidden">"
00000137`8bf03a80  "<rect x="535" y="902" width="21""
00000137`8bf03ac0  " height="198" fill="#61631C"/><r"
00000137`8bf03b00  "ect x="882" y="181" width="61" h"
00000137`8bf03b40  "eight="96" fill="#2FE681"/><rect"
00000137`8bf03b80  " x="854" y="611" width="112" hei"
00000137`8bf03bc0  "ght="123" fill="#F678E7"/><rect "
00000137`8bf03c00  "x="895" y="312" width="84" heigh"
00000137`8bf03c40  "t="39" fill="#8F0671"/><rect x=""
kd> du rcx + rdx - 5
00000137`8bf1c35c  ""/><rect x="432" y="243" width=""
00000137`8bf1c39c  "30" height="155" fill="#9ABA58"/"
00000137`8bf1c3dc  "><rect x="614" y="388" width="40"
00000137`8bf1c41c  "" height="59" fill="#A025FE"/><r"
00000137`8bf1c45c  "ect x="718" y="831" width="11" h"
00000137`8bf1c49c  "eight="135" fill="#64E605"/><rec"
00000137`8bf1c4dc  "t x="194" y="210" width="57" hei"
00000137`8bf1c51c  "ght="187" fill="#89484C"/><rect "
00000137`8bf1c55c  "x="530" y="708" width="23" heigh"
00000137`8bf1c59c  "t="116" fill="#53B311"/><rect x="
00000137`8bf1c5dc  ""226" y="373" width="139" height"
00000137`8bf1c61c  "="120" fill="#F0036F"/><rect x=""
kd> du rcx + rdx * 2 - 5
00000137`8bf34d3d  "最㸀"
kd> du rcx + rdx * 2 - 50
00000137`8bf34cf2  ""50" height="142" fill="#6A84F5""
00000137`8bf34d32  "/></svg>"
```






















