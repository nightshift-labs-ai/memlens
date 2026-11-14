# docs/img

`hookchain.svg` and `hookchain.png` show the hook chain that MemLens's code links in IDA, as `patchscan.py --links`
computes it, for the two `kernel.elf` files of the [demo-data release](https://github.com/nightshift-labs-ai/memlens/releases/tag/demo-data).
They are drawn from `patchscan.py --links` output. They are not IDA screenshots: MemLens has not been run inside real IDA yet.

## What the picture shows

- **Top panel:** `memlens-demo-testhook.zip`. The test module `memlens_testhook` ([tests/vm/testhook](../../tests/vm/testhook/README.md)) hooks `__x64_sys_kill` with an ftrace callback and `__x64_sys_getdents64` with a kprobe. The `bpf_lsm_file_open` lane is systemd's BPF LSM program.
- **Bottom panel:** `memlens-demo-debian13.zip`. The lab VM's script set, through the kernel's tracing (tracefs), an ftrace filter on `vfs_getattr` and a kprobe event (`memlens_kp`) on `do_sys_openat2`. The `bpf_lsm_file_open` lane is the same systemd program again.
- **One lane per patched function entry**, in the order patchscan lists them (by address):
  - **White box:** the hooking instruction (function+offset).
  - **Orange box:** the hook page it calls, copied from memory. The top line is the name MemLens gives the page in IDA, and the line under it is the exporter's `memlens_target_` label.
  - **Blue box:** the page's first named call and its kind.
  - **Purple box, owner name in bold:** who put the hook there. The colour is neutral on purpose: most of these owners are benign.
- **Arrow labels:** the xref types (`call`) and how patchscan found the owner (`ftrace_ops`, `kprobe`, `BPF program`).
- **No hand-written words:** the picture has no headings or legend of its own. Every word in it is a piece of the `--links` output, and this page and the caption explain the rest.

## How they were made

1. **SVG:**

   ```
   python3 tools/hookgraph.py <testhook kernel.elf> <demo kernel.elf> -o docs/img/hookchain.svg
   ```

   - **Inputs:** the `kernel.elf` from each zip, by sha256:
     - `memlens-demo-testhook.zip`: `8d95998eacc39055c81417983f3dcdf7bea1d1c811272b13725035971dd149f9`.
     - `memlens-demo-debian13.zip`: `1481bdbfd0d12b907e208b873d5810c6d1e2adacdf8dbc9cebfb0ae8ad80efa5`.
   - **Code path:** the tool runs the same code as `patchscan.py --links`: `scan`, `hook_links`, `hook_xrefs`, `role_names`, `page_owners` and `at`. It types no labels.
   - **Format:** plain `<text>` in the generic `monospace` font. There are no fonts, scripts, styles or links, because GitHub sanitises SVG. The same inputs give the same bytes.
2. **PNG:** rasterised offline from the SVG with Playwright's Chromium headless shell (`chromium_headless_shell-1155`).
   - **Settings:** viewport set to the SVG's size (900 x 820), device scale 1.5, so it stays sharp on HiDPI screens. The system's monospace font is DejaVu Sans Mono here.
   - **Result:** 1350 x 1230 px, 224 KB, embedded at width 900.
   - **Script** (Node, with the `playwright` package):

     ```js
     import { chromium } from "playwright"; import fs from "node:fs";
     const [inp, out] = process.argv.slice(2), svg = fs.readFileSync(inp, "utf8");
     const w = +svg.match(/width="(\d+)"/)[1], h = +svg.match(/height="(\d+)"/)[1];
     const b = await chromium.launch(), pg = await b.newPage({ viewport: { width: w, height: h }, deviceScaleFactor: 1.5 });
     await pg.setContent(`<html><body style="margin:0;background:#fff">${svg}</body></html>`);
     await pg.screenshot({ path: out, clip: { x: 0, y: 0, width: w, height: h } }); await b.close();
     ```
3. **Expected texts:** `expected-hook-chain.testhook.txt` and `expected-hook-chain.demo.txt` are copies of each zip's `expected-hook-chain.txt`, the `--links` output the picture is checked against.
   - sha256 `215625d6d2cc8ca3b8c5480be9991800d3fc636085f4308c558a2b727a548394` (testhook). It also holds patchscan's stderr line, `125682 function symbols scanned`.
   - sha256 `4b27595469ef7cf366ac39d673d954b28b89cf2a079288635fc2b6c2e21ed750` (demo).
   - The test compares only the lines patchscan prints on stdout, so a re-uploaded zip whose file drops the stderr line still matches. On a re-export that changes `kernel.elf`, refresh these copies and hashes and redraw.

To redraw after a change to patchscan, run step 1, then step 2 (device scale 1.5), then refresh the texts in step 3 from `patchscan.py --links`, then run `tests/test_hookgraph.py` with both `kernel.elf` files.

## Checked by `tests/test_hookgraph.py`

- **Without the demo files:**
  - The SVG parses with `xml.etree` and has no script, style, image, link or event attribute.
  - Every text node in panel *i* is a piece of one field of sample *i*'s expected text, and each bold text is a piece of an `owner` line.
  - **Lane by lane:**
    - The site, the first arrow's label and the page label are one `xref` line, with that type.
    - The page name is that page's `rename`.
    - The handler and its kind are the entry line's `(calls H, kind)`, and the arrow to it is that `xref`'s type.
    - The owner lines joined are that page's `owner` line, the name in bold, and the arrow to the owner is a piece of it.
    - Every link that `--links` lists is one lane.
  - **The drawing:** each text sits in one box of its kind. Each arrow goes from the right box to the right box, with its head at its end and its label beside it.
  - **Mutants that fail:**
    - An owner renamed, truncated or moved to another lane.
    - A handler, kind, page name or site swapped between lanes.
    - An arrow label changed (`call` to `jump` or `data`, the kprobe owner's `kprobe` to `ftrace_ops`).
    - A hand-typed label, a line kind or two fields as a label, a text outside the panels, a site made bold.
    - An owner box removed, an arrowhead reversed, the panels swapped.
  - The PNG is the SVG's size times 1.5 and under 300 KB.
  - The snippet below has the caption and image paths that exist, and its table is the top panel's lanes, row by row, from the testhook `--links` text.
- **With `MEMLENS_DEMO_ELF` and `MEMLENS_TESTHOOK_ELF`** (or both files as arguments, in any order; each is told apart by its sha256):
  - `patchscan.py --links` on each must print its sample's expected text. If it does not, the test fails and says to redraw.
  - Two runs of the tool give this SVG byte for byte.
  - A `kernel.elf` with another sha256 (your own export) is only checked against its own `--links` output.

## Proposed README snippet

Put this right under the pitch. It is added at merge time.

```markdown
<a href="docs/img/hookchain.svg"><img src="docs/img/hookchain.png" width="900" alt="The hook chain MemLens's code links in IDA, as patchscan.py --links computes it: one lane per patched function, with the hooking call, the hook page copied from memory under its new name, the page's first call, and the owner in bold. Top: the test-module sample; bottom: the demo kernel.elf."></a>

<sub>Drawn by tools/hookgraph.py from `patchscan.py --links` on the two demo kernel.elf files; not an IDA screenshot. Top: `memlens-demo-testhook.zip` (the test module `memlens_testhook` hooks `__x64_sys_kill` and `__x64_sys_getdents64`; systemd's BPF program on `bpf_lsm_file_open`). Bottom: `memlens-demo-debian13.zip` (the lab VM's script set an ftrace filter on `vfs_getattr` and a kprobe event on `do_sys_openat2` through tracefs; the same BPF program). Each lane: the hooking instruction, the hook page copied from memory (orange: the name MemLens gives it over the exporter's label), its first call (blue) and the owner (purple, bold). How it is made: [docs/img](docs/img/README.md).</sub>

The top panel as a table, from the same `--links` text, in the list's order (by address):

| Where | Handler | Owner |
|---|---|---|
| `__x64_sys_kill` | `ftrace_ops_assist_func` (ftrace) | **memlens_testhook.th_kill_callback** (ftrace_ops memlens_testhook.th_kill_ops) |
| `bpf_lsm_file_open` | `__bpf_tramp_enter` (BPF trampoline) | **bpf.bpf_prog_e8932b6bae2b9745_restrict_filesystems** (BPF program) |
| `__x64_sys_getdents64` | `kprobe_ftrace_handler` (kprobe via ftrace) | **memlens_testhook.th_getdents_pre** (kprobe pre_handler) |
```

### Merge notes (for the README front-page branch)

- **Placement:** the snippet goes right under the pitch, with the table directly under the image (field item 9: the picture plus a 3-row table).
- **The existing table:** README's "A hook set by a module" section already has a Where | Owner | Handler table of the same three rows. Keep only one, or turn that one into a pointer up to the hero. Its rows are reordered compared with the list (judge release-day item 5); this table uses the list's order.
- **Link check after inserting:** every relative link and image path in README.md must resolve. `tests/test_hookgraph.py` checks that the snippet's three paths exist, but only the merged README can be checked as a whole:

  ```
  python3 -I -c "import os,re,sys; t=open('README.md').read(); bad=[p for a,b in re.findall(r'(?:src|href)=\"([^\"#]+)\"|\]\(([^)#]+)\)',t) for p in [a or b] if '://' not in p and not p.startswith('mailto:') and not os.path.exists(p)]; print(bad or 'all links resolve'); sys.exit(1 if bad else 0)"
  ```
