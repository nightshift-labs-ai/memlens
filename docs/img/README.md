# docs/img

`hookchain.svg` and `hookchain.png` show the hook chain that MemLens's code links in IDA, as `patchscan.py --links`
computes it, for the two `kernel.elf` files of the [demo-data release](https://github.com/nightshift-labs-ai/memlens/releases/tag/demo-data).
They are drawn from `patchscan.py --links` output. They are not IDA screenshots: MemLens has not been run inside real IDA yet.

## What the picture shows

- **Legend line, at the top:** white = hooked function, orange = hook page MemLens named, blue = handler, purple = owner, each with a square in that box's colours.
- **Top panel, "Hooks set by a test module (second sample)":** `memlens-demo-testhook.zip`. The test module `memlens_testhook` ([tests/vm/testhook](../../tests/vm/testhook/README.md)) hooks `__x64_sys_kill` with an ftrace callback and `__x64_sys_getdents64` with a kprobe. The `bpf_lsm_file_open` lane is systemd's BPF LSM program.
- **Bottom panel, "Hooks set through tracefs (demo)":** `memlens-demo-debian13.zip`. The lab VM's script set, through the kernel's tracing (tracefs), an ftrace filter on `vfs_getattr` and a kprobe event (`memlens_kp`) on `do_sys_openat2`. The `bpf_lsm_file_open` lane is the same systemd program again.
- **One lane per patched function entry**, in the order patchscan lists them (by address):
  - **White box:** the hooking instruction (function+offset).
  - **Orange box:** the hook page it calls, copied from memory. The top line is the name MemLens gives the page in IDA, and the line under it is the exporter's `memlens_target_` label.
  - **Blue box:** the page's first named call and its kind.
  - **Purple box, owner name in bold:** who put the hook there. The colour is neutral on purpose: most of these owners are benign.
- **Arrow labels:** the xref types (`call`) and how patchscan found the owner (`ftrace_ops`, `kprobe`, `BPF program`).
- **The tool's own words are only the two panel headings and the legend line.** They are fixed strings in `tools/hookgraph.py` (`HEADINGS`, `LEGEND`). A panel gets its heading only when its `kernel.elf` is one of the two demo files, by sha256; any other `kernel.elf` gets none. Every other word in the picture is a piece of the `--links` output, and this page and the caption explain the rest.

## How they were made

1. **SVG:**

   ```
   python3 tools/hookgraph.py <testhook kernel.elf> <demo kernel.elf> -o docs/img/hookchain.svg
   ```

   - **Inputs:** the `kernel.elf` from each zip, by sha256:
     - `memlens-demo-testhook.zip`: `8d95998eacc39055c81417983f3dcdf7bea1d1c811272b13725035971dd149f9`.
     - `memlens-demo-debian13.zip`: `1481bdbfd0d12b907e208b873d5810c6d1e2adacdf8dbc9cebfb0ae8ad80efa5`.
   - **Code path:** the tool runs the same code as `patchscan.py --links`: `scan`, `hook_links`, `hook_xrefs`, `role_names`, `page_owners` and `at`. It types no labels in the lanes; its only own words are the headings and the legend.
   - **Format:** plain `<text>` in the generic `monospace` font. There are no fonts, scripts, styles or links, because GitHub sanitises SVG. The same inputs give the same bytes.
2. **PNG:** rasterised offline from the SVG with Playwright's Chromium headless shell (`chromium_headless_shell-1155`).
   - **Settings:** viewport set to the SVG's size (900 x 896), device scale 1.5, so it stays sharp on HiDPI screens. The system's monospace font is DejaVu Sans Mono here.
   - **Result:** 1350 x 1344 px, 248 KB, embedded at width 900.
   - **Hashes:** rendered from hookchain.svg sha256 3b3a5a02dc16ae297da23d75761e6c9fc00c276be14c276db02834c68cdd3f57; hookchain.png sha256 45020c145f049b97c8d57ea473d661d25b8672125e27dc8fdcc16666ac125d98. `tests/test_hookgraph.py` checks this pair (its `RENDERED`), because README.md shows the PNG: a redrawn SVG needs a new PNG, and both hashes change here and in the test. The script below gives these PNG bytes again from this SVG here; another machine's fonts may give other bytes.
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

To redraw after a change to patchscan, run step 1, then step 2 (device scale 1.5) and update its two hashes here and in the test's `RENDERED`, then refresh the texts in step 3 from `patchscan.py --links`, then run `tests/test_hookgraph.py` with both `kernel.elf` files.

## Checked by `tests/test_hookgraph.py`

- **Without the demo files:**
  - The SVG parses with `xml.etree` and has no script, style, image, link or event attribute.
  - Every text node in panel *i* is a piece of one field of sample *i*'s expected text, and each bold text is a piece of an `owner` line.
  - **The only exceptions are the tool's own words**, typed again in the test so that a changed word fails:
    - Panel *i*'s heading, exactly `Hooks set by a test module (second sample)` (top) or `Hooks set through tracefs (demo)` (bottom), at the top of its panel, outside the lanes. A panel drawn from any other `kernel.elf` has no heading.
    - The legend line above the panels, exactly `white = hooked function`, `orange = hook page MemLens named`, `blue = handler`, `purple = owner`, in that order. Each square is in the fill and border colours of its role's boxes, and every box of that role has those colours.
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
    - A heading reworded, swapped between the panels, dropped, doubled into a lane or replaced by a `--links` word.
    - The legend reworded, reordered, recoloured, extended or dropped, and a box recoloured.
  - The PNG is the SVG's size times 1.5 and under 300 KB, and the sha256 pair of the SVG and the PNG is the one step 2 records (the test's `RENDERED`), so a PNG not rendered from this SVG fails.
  - The snippet below has the caption and image paths that exist, README.md holds its lines as they are, its alt text names each panel's hooked functions in the picture's order, and the table under it is the top panel's lanes, row by row, from the testhook `--links` text.
- **With `MEMLENS_DEMO_ELF` and `MEMLENS_TESTHOOK_ELF`** (or both files as arguments, in any order; each is told apart by its sha256):
  - `patchscan.py --links` on each must print its sample's expected text. If it does not, the test fails and says to redraw.
  - Two runs of the tool give this SVG byte for byte.
  - A `kernel.elf` with another sha256 (your own export) is only checked against its own `--links` output.

## README snippet

README.md has this right under its pitch (the test checks that README.md holds these lines as they are):

```markdown
<a href="docs/img/hookchain.svg"><img src="docs/img/hookchain.png" width="900" alt="Hook chain diagram drawn from patchscan.py --links output on the two demo kernel.elf files, not an IDA screenshot. Legend: white = hooked function, orange = hook page MemLens named, blue = handler, purple = owner. Top panel, hooks set by a test module (second sample): __x64_sys_kill hooked through ftrace, owner memlens_testhook.th_kill_callback; bpf_lsm_file_open, owner systemd's BPF program; __x64_sys_getdents64 hooked by a kprobe, owner memlens_testhook.th_getdents_pre. Bottom panel, hooks set through tracefs (demo, Debian 13 6.12 memory image): bpf_lsm_file_open, the same BPF program; do_sys_openat2, owner the tracefs kprobe memlens_kp; vfs_getattr, owner function_trace_call (ftrace_ops global_ops)."></a>

<sub>Drawn by tools/hookgraph.py from `patchscan.py --links` on the two demo kernel.elf files; not an IDA screenshot. One lane per hooked function: the hooking call, the hook page copied from memory under the name MemLens's code gives it in IDA (the exporter's label under it), the page's first named call, and the owner in bold. The hook on `bpf_lsm_file_open` is systemd's BPF LSM program in both captures. How it is made and checked: [docs/img](docs/img/README.md).</sub>
```

The top panel as a table, from the same `--links` text, in the list's order (by address). README.md does not repeat it: its section "A hook set by a module" already has these three rows, as Where | Owner | Handler.

| Where | Handler | Owner |
|---|---|---|
| `__x64_sys_kill` | `ftrace_ops_assist_func` (ftrace) | **memlens_testhook.th_kill_callback** (ftrace_ops memlens_testhook.th_kill_ops) |
| `bpf_lsm_file_open` | `__bpf_tramp_enter` (BPF trampoline) | **bpf.bpf_prog_e8932b6bae2b9745_restrict_filesystems** (BPF program) |
| `__x64_sys_getdents64` | `kprobe_ftrace_handler` (kprobe via ftrace) | **memlens_testhook.th_getdents_pre** (kprobe pre_handler) |

### How README.md uses it

- **Placement:** in README.md the snippet sits right under the pitch and the line on who built MemLens. That line also says, before the picture, that MemLens has not yet been run in a real IDA, because the picture pushes the Status line under Install below the first screen.
- **The table:** README.md keeps its narrow Where | Owner | Handler tables (the demo's under Before and after, the second sample's under "A hook set by a module", in the list's order) and adds no third one.
- **Link check:** every relative link and image path in README.md must resolve. `tests/test_hookgraph.py` checks that the snippet's three paths exist and that README.md holds the snippet; this one-liner, run in the repository folder, checks the file part of every relative link and image path in the whole README, also of the links with a `#fragment` (`docs/OUTPUT.md#details` must name an existing `docs/OUTPUT.md`):

  ```
  python3 -I -c "import os,re,sys; t=open('README.md').read(); ps=[p for a,b in re.findall(r'(?:src|href)=\"([^\"]+)\"|\]\(([^)\s]+)\)',t) for p in [(a or b).split('#')[0]] if p and '://' not in p and not p.startswith('mailto:')]; bad=[p for p in ps if not os.path.exists(p)]; print(len(ps),'file links;', bad or 'all resolve'); sys.exit(1 if bad else 0)"
  ```

  It checks files only: the anchors (`#install`, `#details`, ...) need a manual check against the headings.
