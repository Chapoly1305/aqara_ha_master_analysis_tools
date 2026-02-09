import os
from collections import deque

import idaapi
import idautils
import idc
import ida_segment
import ida_bytes
import ida_funcs

try:
    import ida_hexrays
    import ida_lines
except Exception:
    ida_hexrays = None
    ida_lines = None

TARGETS = ["system_run", "system_command"]
SINK_KEYWORDS = ("system", "popen")
DECOMP_CACHE = {}


def wait_for_analysis():
    try:
        idaapi.auto_wait()
    except Exception:
        try:
            idaapi.autoWait()
        except Exception:
            pass


def get_strings():
    out = []
    s = idautils.Strings()
    try:
        s.setup(strtypes=idaapi.STRTYPE_C)
    except Exception:
        s.setup()
    for item in s:
        out.append((item.ea, str(item)))
    return out


def seg_class(ea):
    seg = ida_segment.getseg(ea)
    if not seg:
        return ""
    return ida_segment.get_segm_class(seg) or ""


def is_code_ea(ea):
    return seg_class(ea) == "CODE"


def is_data_ea(ea):
    return seg_class(ea) in {"DATA", "BSS", "CONST", "RODATA"}


def seg_bounds(ea):
    seg = ida_segment.getseg(ea)
    if seg:
        try:
            return seg.start_ea, seg.end_ea
        except Exception:
            pass
    # Backward-compat fallback for older IDA APIs.
    try:
        return ida_segment.get_segm_start(ea), ida_segment.get_segm_end(ea)
    except Exception:
        return None, None


def pointer_refs_to_ea(target_ea):
    refs = []
    for seg_ea in idautils.Segments():
        sc = seg_class(seg_ea)
        if sc not in {"DATA", "BSS", "CONST", "RODATA"}:
            continue
        start, end = seg_bounds(seg_ea)
        if start is None or end is None:
            continue
        ea = start
        while ea + 4 <= end:
            if ida_bytes.get_dword(ea) == target_ea:
                refs.append(ea)
            ea += 4
    return refs


def collect_code_xrefs(str_ea):
    found = []

    # 1) direct xrefs
    for xr in idautils.XrefsTo(str_ea):
        frm = xr.frm
        if is_code_ea(frm):
            found.append((frm, [str_ea]))
        elif is_data_ea(frm):
            for xr2 in idautils.XrefsTo(frm):
                if is_code_ea(xr2.frm):
                    found.append((xr2.frm, [str_ea, frm]))

    # 2) pointer-table style refs
    if not found:
        for ptr_ea in pointer_refs_to_ea(str_ea):
            for xr in idautils.XrefsTo(ptr_ea):
                if is_code_ea(xr.frm):
                    found.append((xr.frm, [str_ea, ptr_ea]))

    # dedupe
    uniq = {}
    for ea, chain in found:
        if ea not in uniq:
            uniq[ea] = chain
    return [(ea, uniq[ea]) for ea in sorted(uniq.keys())]


def decompile_func(func_ea):
    if func_ea in DECOMP_CACHE:
        return DECOMP_CACHE[func_ea]
    if not ida_hexrays:
        DECOMP_CACHE[func_ea] = None
        return None
    if not ida_hexrays.init_hexrays_plugin():
        DECOMP_CACHE[func_ea] = None
        return None
    try:
        cfunc = ida_hexrays.decompile(func_ea)
    except Exception:
        DECOMP_CACHE[func_ea] = None
        return None
    txt = str(cfunc)
    if ida_lines:
        try:
            txt = ida_lines.tag_remove(txt)
        except Exception:
            pass
    DECOMP_CACHE[func_ea] = txt
    return txt


def context_lines(text, needle, radius=6):
    lines = text.splitlines()
    idx = [i for i, line in enumerate(lines) if needle in line]
    if not idx:
        return None
    blocks = []
    for i in idx:
        s = max(0, i - radius)
        e = min(len(lines), i + radius + 1)
        blocks.append("\n".join(lines[s:e]))
    return "\n\n---\n\n".join(blocks)


def resolve_func(ea, create=False):
    func = idaapi.get_func(ea)
    if func:
        return func
    if not create or not is_code_ea(ea):
        return None
    # Some samples keep code decoded but do not auto-create a function at xref start.
    if ida_funcs.add_func(ea):
        wait_for_analysis()
        return idaapi.get_func(ea)
    return None


def sink_text_match(text):
    if not text:
        return False
    low = text.lower()
    if "system_run" in low or "system_command" in low:
        return False
    return any(k in low for k in SINK_KEYWORDS)


def ea_names(ea):
    names = []
    if ea == idaapi.BADADDR:
        return names
    n0 = idaapi.get_name(ea)
    if n0:
        names.append(n0)
    fn = idaapi.get_func(ea)
    if fn:
        n1 = idaapi.get_func_name(fn.start_ea)
        if n1:
            names.append(n1)
    try:
        n2 = idc.get_name(ea)
        if n2:
            names.append(n2)
    except Exception:
        pass
    return list(dict.fromkeys(names))


def call_refs_from_insn(insn_ea):
    refs = []
    mnem = (idc.print_insn_mnem(insn_ea) or "").lower()
    op0 = idc.print_operand(insn_ea, 0) or ""
    if not mnem:
        return refs
    # Keep this broad enough for MIPS and generic call mnemonics.
    if not (
        mnem.startswith("jal")
        or mnem in {"call", "bl", "blr", "blx", "bsr", "jsr"}
    ):
        return refs
    for r in idautils.CodeRefsFrom(insn_ea, 0):
        if r != idc.next_head(insn_ea):
            refs.append((r, op0))
    if not refs:
        refs.append((idaapi.BADADDR, op0))
    return refs


def function_callees(func_ea):
    out = []
    fn = idaapi.get_func(func_ea)
    if not fn:
        return out
    seen = set()
    for insn_ea in idautils.FuncItems(fn.start_ea):
        if not ida_bytes.is_code(ida_bytes.get_full_flags(insn_ea)):
            continue
        for tgt, op0 in call_refs_from_insn(insn_ea):
            key = (tgt, op0)
            if key in seen:
                continue
            seen.add(key)
            out.append((tgt, insn_ea, op0))
    return out


def sink_paths_from(start_func_ea, max_depth=8, max_paths=3, max_nodes=800):
    paths = []
    q = deque()
    q.append((start_func_ea, [start_func_ea], []))
    visited = {start_func_ea}
    expanded = 0

    while q and len(paths) < max_paths and expanded < max_nodes:
        cur, func_path, edge_path = q.popleft()
        expanded += 1
        if len(func_path) - 1 >= max_depth:
            continue

        for tgt, callsite, op0 in function_callees(cur):
            # Direct sink by operand text or target naming.
            sink_hit = sink_text_match(op0)
            sink_name = None
            callee_name = None
            callee_func_ea = None
            if tgt != idaapi.BADADDR:
                names = ea_names(tgt)
                sink_name = next((n for n in names if sink_text_match(n)), None)
                if sink_name:
                    sink_hit = True
                fn_tgt = resolve_func(tgt, create=True)
                if fn_tgt:
                    callee_func_ea = fn_tgt.start_ea
                    callee_name = idaapi.get_func_name(callee_func_ea)
                elif names:
                    callee_name = names[0]

            edge = {
                "from_func": cur,
                "callsite": callsite,
                "to_ea": tgt if tgt != idaapi.BADADDR else None,
                "to_func": callee_func_ea,
                "to_name": callee_name or op0 or "<unknown>",
            }

            if sink_hit:
                paths.append(
                    {
                        "func_path": list(func_path),
                        "edge_path": edge_path + [edge],
                        "sink_ea": tgt if tgt != idaapi.BADADDR else None,
                        "sink_name": sink_name or op0,
                        "callsite": callsite,
                    }
                )
                if len(paths) >= max_paths:
                    break
                continue

            if tgt == idaapi.BADADDR:
                continue
            callee = resolve_func(tgt, create=True)
            if not callee:
                continue
            nxt = callee.start_ea
            if nxt in visited:
                continue
            visited.add(nxt)
            q.append((nxt, func_path + [nxt], edge_path + [edge]))
    return paths


def fmt_func(ea):
    fn = idaapi.get_func(ea)
    if fn:
        return f"{idaapi.get_func_name(fn.start_ea)}@0x{fn.start_ea:X}"
    name = idaapi.get_name(ea)
    if name:
        return f"{name}@0x{ea:X}"
    return f"0x{ea:X}"


def normalize_token(token):
    if not token:
        return ""
    return token.split("@", 1)[0].strip()


def extract_first_match_block(text, patterns, radius=5):
    if not text:
        return None
    lines = text.splitlines()
    lowered = [ln.lower() for ln in lines]
    pats = [p.lower() for p in patterns if p]
    for idx, line in enumerate(lowered):
        if any(p in line for p in pats):
            s = max(0, idx - radius)
            e = min(len(lines), idx + radius + 1)
            return "\n".join(lines[s:e])
    return None


def step_snippet(edge):
    """
    Show decompiled snippet in the caller function for this edge.
    This usually reveals how command/data is passed into the next wrapper or sink.
    """
    from_ea = edge.get("from_func")
    if from_ea is None:
        return None
    decomp = decompile_func(from_ea)
    if not decomp:
        return None
    to_name = normalize_token(edge.get("to_name", ""))
    pats = [to_name]
    # Add broad sink patterns so final step can show popen/system call even with renamed symbols.
    pats.extend([f"{k}(" for k in SINK_KEYWORDS])
    return extract_first_match_block(decomp, pats, radius=6)


def main():
    wait_for_analysis()

    args = idc.ARGV[1:]
    report_path = args[0] if args else os.path.join(os.getcwd(), "ida_system_strings.md")
    input_path = idaapi.get_input_file_path()

    s_map = {k: [] for k in TARGETS}
    for ea, s in get_strings():
        if s in s_map:
            s_map[s].append(ea)

    out = []
    out.append("# IDA Report: system_run / system_command")
    out.append("")
    out.append(f"**Binary**: `{input_path}`")
    out.append("")

    for target in TARGETS:
        out.append(f"## `{target}`")
        out.append("")
        entries = s_map[target]
        if not entries:
            out.append("Not found.")
            out.append("")
            continue

        for s_ea in entries:
            out.append(f"- String EA: `0x{s_ea:X}`")
            xrefs = collect_code_xrefs(s_ea)
            if not xrefs:
                out.append("  - Xrefs: none")
                out.append("")
                continue

            for x_ea, chain in xrefs:
                func = resolve_func(x_ea, create=True)
                func_name = idaapi.get_func_name(x_ea) if func else "<no function>"
                func_ea = func.start_ea if func else None
                func_ea_s = f"0x{func_ea:X}" if func_ea is not None else "n/a"
                out.append(f"  - Xref EA: `0x{x_ea:X}` | Function: `{func_name}` @ `{func_ea_s}`")
                out.append("    - Xref chain: `" + " -> ".join(f"0x{v:X}" for v in chain) + "`")

                if func_ea is not None:
                    sink_paths = sink_paths_from(func_ea)
                    if sink_paths:
                        out.append("    - Call-chain to libc sink:")
                        for idx, p in enumerate(sink_paths, start=1):
                            sink_text = p["sink_name"] or (
                                f"0x{p['sink_ea']:X}" if p["sink_ea"] is not None else "<unknown>"
                            )
                            out.append(f"      - Chain {idx}: sink `{sink_text}`")
                            out.append(f"        - Anchor: xref `0x{x_ea:X}` in `{fmt_func(func_ea)}`")
                            for step_no, edge in enumerate(p.get("edge_path", []), start=1):
                                from_text = fmt_func(edge["from_func"])
                                if edge.get("to_func") is not None:
                                    to_text = fmt_func(edge["to_func"])
                                elif edge.get("to_ea") is not None:
                                    to_text = f"{edge.get('to_name', '<unknown>')}@0x{edge['to_ea']:X}"
                                else:
                                    to_text = edge.get("to_name", "<unknown>")
                                out.append(
                                    f"        - Step {step_no}: `{from_text}` --[`0x{edge['callsite']:X}`]--> `{to_text}`"
                                )
                                snippet = step_snippet(edge)
                                if snippet:
                                    out.append(f"        - Step {step_no} Decompiled snippet:")
                                    out.append("")
                                    out.append("```c")
                                    out.append(snippet)
                                    out.append("```")
                    else:
                        out.append("    - Call-chain to libc sink: none found (within depth 8)")

                    decomp = decompile_func(func_ea)
                    if decomp:
                        ctx = context_lines(decomp, target)
                        if ctx:
                            out.append("    - Decompiled context:")
                            out.append("")
                            out.append("```c")
                            out.append(ctx)
                            out.append("```")
            out.append("")

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")

    idaapi.msg(f"[ida_system_strings] Wrote report: {report_path}\\n")
    idc.qexit(0)


if __name__ == "__main__":
    main()
