# docs/img

`hookchain.svg` and `hookchain.png` show the hook chain that MemLens adds in IDA, for the two `kernel.elf` files of the
[demo-data release](https://github.com/nightshift-labs-ai/memlens/releases/tag/demo-data). They are drawn from
`patchscan.py --links` output. They are not IDA screenshots: MemLens has not been run inside real IDA yet.

## What the picture shows

- **Top panel:** `memlens-demo-debian13.zip`. The kernel's own tracing set an ftrace filter on `vfs_getattr` and a kprobe on `do_sys_openat2`, and systemd's BPF LSM program runs on `bpf_lsm_file_open`.
- **Bottom panel:** `memlens-demo-testhook.zip`. The test module `memlens_testhook` ([tests/vm/testhook](../../tests/vm/testhook/README.md)) hooks `__x64_sys_kill` with an ftrace callback and `__x64_sys_getdents64` with a kprobe. The `bpf_lsm_file_open` lane is the same systemd program again.
- **One lane per patched function entry**, in the order patchscan lists them (by address):
  - **White box:** the hooking instruction (function+offset).
  - **Orange box:** the hook page it calls, copied from memory. The top line is the name MemLens gives the page in IDA, and the line under it is the exporter's `memlens_target_` label.
  - **Blue box:** the page's first named call and its kind.
  - **Red box, owner name in bold:** who put the hook there.
- **Arrow labels:** the xref type (`call`) and how patchscan found the owner (`ftrace_ops`, `kprobe`, `BPF program`).
- **No hand-written words:** the picture has no headings or legend of its own. Every word in it is a piece of the `--links` output, and this page and the caption explain the rest.

## How they were made

1. **SVG:**

   ```
   python3 tools/hookgraph.py <demo kernel.elf> <testhook kernel.elf> -o docs/img/hookchain.svg
   ```

   - **Inputs:** the `kernel.elf` from each zip:
     - `memlens-demo-debian13.zip`: zip sha256 `e29128167eddaa7dda9f04dde75e03345c441585d9ebe987e6d9bd01e6b70134`, kernel.elf `1481bdbfd0d12b907e208b873d5810c6d1e2adacdf8dbc9cebfb0ae8ad80efa5`.
     - `memlens-demo-testhook.zip`: zip `753c3e989d4926a16d26ab72a358178ffeb2f0c607eb877128550477eff32e27`, kernel.elf `8d95998eacc39055c81417983f3dcdf7bea1d1c811272b13725035971dd149f9`.
   - **Code path:** the tool runs the same code as `patchscan.py --links`: `scan`, `hook_links`, `role_names`, `page_owners` and `at`. It types no labels.
   - **Format:** plain `<text>` in the generic `monospace` font. There are no fonts, scripts, styles or links, because GitHub sanitises SVG. The same inputs give the same bytes.
2. **PNG:** rasterised offline from the SVG with Playwright's Chromium headless shell (`chromium_headless_shell-1155`).
   - **Settings:** viewport set to the SVG's size, device scale 1. The system's monospace font is DejaVu Sans Mono here.
   - **Result:** 900 x 820 px.
3. **Expected texts:** `expected-hook-chain.demo.txt` and `expected-hook-chain.testhook.txt` are byte copies of each zip's `expected-hook-chain.txt`, the `--links` output the picture is checked against.
   - sha256 `4b27595469ef7cf366ac39d673d954b28b89cf2a079288635fc2b6c2e21ed750` (demo).
   - sha256 `215625d6d2cc8ca3b8c5480be9991800d3fc636085f4308c558a2b727a548394` (testhook).
   - The testhook file also holds patchscan's stderr line, `125682 function symbols scanned`.

To redraw after a change to patchscan, run step 1, then step 2 with any SVG-to-PNG converter at device scale 1, then `tests/test_hookgraph.py`.

## Checked by `tests/test_hookgraph.py`

- **Without the demo files:**
  - The SVG parses with `xml.etree` and has no script, style, image, link or event attribute.
  - Every text node in panel *i* is a substring of sample *i*'s expected text, and each bold text is a piece of an `owner` line.
  - There is one lane per patched entry, each with its owner in bold.
  - Mutants fail: an owner renamed, an edge label changed, a hand-typed label, a text outside the panels, a site made bold, the panels swapped.
  - The PNG is as large as the SVG and under 300 KB.
  - This page has the caption.
- **With `MEMLENS_DEMO_ELF` and `MEMLENS_TESTHOOK_ELF`** (or both files as arguments):
  - `patchscan.py --links` prints each sample's expected text.
  - Two runs of the tool give this SVG byte for byte.

## Proposed README snippet

Put this right under the pitch. It is added at merge time.

```markdown
[![The hook chain MemLens adds in IDA, one lane per patched function: the hooking call, the hook page copied from memory under its new name, the page's first call, and the owner in bold. Top: the demo kernel.elf; bottom: the test-module sample.](docs/img/hookchain.png)](docs/img/hookchain.svg)

<sub>Drawn by tools/hookgraph.py from `patchscan.py --links` on the two demo kernel.elf files; not an IDA screenshot. Top: `memlens-demo-debian13.zip` (kernel tracing on `vfs_getattr` and `do_sys_openat2`, systemd's BPF program on `bpf_lsm_file_open`). Bottom: `memlens-demo-testhook.zip` (the test module `memlens_testhook` hooks `__x64_sys_kill` and `__x64_sys_getdents64`). Each lane: the hooking instruction, the hook page copied from memory (orange: the name MemLens gives it over the exporter's label), its first call (blue) and the owner (red, bold). How it is made: [docs/img](docs/img/README.md).</sub>
```
