import os
import re
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog


class RabbitFXTool:
    def __init__(self, root):
        self.root = root
        self.root.title("WWMI RabbitFX Maker")

        self.ini_path = None
        self.components = []
        self.component_changes = {}

        self._build_ui()

    def _build_ui(self):
        file_frame = tk.Frame(self.root)
        file_frame.pack(fill="x", padx=10, pady=10)

        tk.Label(file_frame, text="mod.ini path:").pack(side="left")

        self.entry_path = tk.Entry(file_frame, width=60)
        self.entry_path.pack(side="left", padx=5)

        btn_browse = tk.Button(file_frame, text="Browse...", command=self.browse_ini)
        btn_browse.pack(side="left")

        btn_scan = tk.Button(file_frame, text="Scan", command=self.scan_components)
        btn_scan.pack(side="left", padx=5)

        list_frame = tk.Frame(self.root)
        list_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        tk.Label(list_frame, text="Components:").pack(anchor="w")

        self.listbox = tk.Listbox(list_frame, height=10)
        self.listbox.pack(fill="both", expand=True, side="left")

        scrollbar = tk.Scrollbar(list_frame, orient="vertical", command=self.listbox.yview)
        scrollbar.pack(side="right", fill="y")
        self.listbox.config(yscrollcommand=scrollbar.set)

        btn_frame = tk.Frame(self.root)
        btn_frame.pack(fill="x", padx=10, pady=10)

        btn_glow = tk.Button(btn_frame, text="Add Glow", command=self.add_glow)
        btn_glow.pack(side="left")

        btn_fx = tk.Button(btn_frame, text="Add FX", command=self.add_fx)
        btn_fx.pack(side="left", padx=5)

        btn_remove = tk.Button(btn_frame, text="Remove Glow/FX", command=self.remove_rabbitfx)
        btn_remove.pack(side="left", padx=5)

        btn_apply = tk.Button(btn_frame, text="Apply", command=self.apply_changes)
        btn_apply.pack(side="right")

        self.status_label = tk.Label(self.root, text="Select mod.ini and scan.", anchor="w")
        self.status_label.pack(fill="x", padx=10, pady=(0, 10))

    def browse_ini(self):
        path = filedialog.askopenfilename(
            title="Select mod.ini",
            filetypes=[("INI files", "*.ini"), ("All files", "*.*")]
        )
        if path:
            self.ini_path = path
            self.entry_path.delete(0, tk.END)
            self.entry_path.insert(0, path)
            self.status_label.config(text=f"Selected: {path}")
            self.scan_components()

    def scan_components(self):
        path = self.entry_path.get().strip()
        if not path or not os.path.isfile(path):
            messagebox.showerror("Error", "Invalid file.")
            return

        self.ini_path = path

        try:
            with open(path, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except:
            with open(path, "r", encoding="cp949", errors="ignore") as f:
                lines = f.readlines()

        comp_set = set()
        pattern = re.compile(r"^\[TextureOverrideComponent(\d+)\]", re.IGNORECASE)

        for line in lines:
            m = pattern.match(line.strip())
            if m:
                comp_set.add(int(m.group(1)))

        self.components = sorted(comp_set)
        self.listbox.delete(0, tk.END)
        for c in self.components:
            self.listbox.insert(tk.END, f"Component {c}")

        self.status_label.config(text=f"Components: {len(self.components)} found")

    def get_selected_component(self):
        sel = self.listbox.curselection()
        if not sel:
            messagebox.showerror("Error", "Select a component.")
            return None
        return self.components[sel[0]]

    def add_glow(self):
        comp = self.get_selected_component()
        if comp is None:
            return

        h = simpledialog.askstring("Glow", "h value:", parent=self.root)
        if h is None: return
        s = simpledialog.askstring("Glow", "s value:", parent=self.root)
        if s is None: return
        v = simpledialog.askstring("Glow", "v value:", parent=self.root)
        if v is None: return
        brightness = simpledialog.askstring("Glow", "brightness:", parent=self.root)
        if brightness is None: return

        glow_name = simpledialog.askstring(
            "Glow",
            "Glow texture (.dds):",
            parent=self.root,
        )
        if not glow_name: return
        glow_name = glow_name.strip()

        if comp not in self.component_changes:
            self.component_changes[comp] = {}
        if "remove" in self.component_changes[comp]:
            del self.component_changes[comp]["remove"]

        self.component_changes[comp]["glow"] = {
            "h": h.strip(),
            "s": s.strip(),
            "v": v.strip(),
            "brightness": brightness.strip(),
            "filename": glow_name,
        }
        self.status_label.config(text=f"Glow queued for Component {comp}")

    def add_fx(self):
        comp = self.get_selected_component()
        if comp is None:
            return

        fx_name = simpledialog.askstring(
            "FX",
            "FX texture (.dds):",
            parent=self.root,
        )
        if not fx_name: return
        fx_name = fx_name.strip()

        if comp not in self.component_changes:
            self.component_changes[comp] = {}
        if "remove" in self.component_changes[comp]:
            del self.component_changes[comp]["remove"]

        self.component_changes[comp]["fx"] = {"filename": fx_name}
        self.status_label.config(text=f"FX queued for Component {comp}")

    def remove_rabbitfx(self):
        comp = self.get_selected_component()
        if comp is None:
            return

        ans = messagebox.askyesno(
            "Remove",
            f"Remove RabbitFX from Component {comp}?"
        )
        if not ans:
            return

        self.component_changes[comp] = {"remove": True}
        self.status_label.config(text=f"Removal queued for Component {comp}")

    @staticmethod
    def _find_component_sections(lines):
        sections = {}
        pattern = re.compile(r"^\[TextureOverrideComponent(\d+)\]", re.IGNORECASE)

        current = None
        start = None

        for i, line in enumerate(lines):
            m = pattern.match(line.strip())
            if m:
                if current is not None:
                    sections[current] = (start, i)
                current = int(m.group(1))
                start = i

        if current is not None:
            sections[current] = (start, len(lines))
        return sections

    def apply_changes(self):
        if not self.ini_path:
            messagebox.showerror("Error", "No INI selected.")
            return
        if not self.component_changes:
            messagebox.showinfo("Info", "No changes.")
            return

        try:
            with open(self.ini_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except:
            with open(self.ini_path, "r", encoding="cp949", errors="ignore") as f:
                lines = f.readlines()

        comp_sections = self._find_component_sections(lines)

        def has_rabbitfx(block):
            s = block.lower()
            return (
                "\\rabbitfx\\" in s
                or "resource\\rabbitfx" in s
                or "commandlist\\rabbitfx\\run" in s
            )

        overwrite = {}
        for comp, cfg in self.component_changes.items():
            if comp not in comp_sections:
                continue
            start, end = comp_sections[comp]
            block = "".join(lines[start:end])
            exists = has_rabbitfx(block)
            if exists:
                ans = messagebox.askyesno(
                    "Overwrite",
                    f"RabbitFX already exists in Component {comp}.\nOverwrite?"
                )
                overwrite[comp] = ans
            else:
                overwrite[comp] = True

        modifies = {
            comp: cfg
            for comp, cfg in self.component_changes.items()
            if comp in comp_sections and overwrite.get(comp)
        }
        if not modifies:
            return

        backup = self.ini_path + ".bak"
        with open(backup, "w", encoding="utf-8") as fbak:
            fbak.writelines(lines)

        new_lines = []

        pattern_header = re.compile(r"^\[TextureOverrideComponent(\d+)\]", re.IGNORECASE)
        current_comp = None
        inside = False
        inserted = {}

        def is_rabbitfx_line(line):
            l = line.lstrip().lower()
            if l.startswith("$\\rabbitfx\\h"): return True
            if l.startswith("$\\rabbitfx\\s"): return True
            if l.startswith("$\\rabbitfx\\v"): return True
            if l.startswith("$\\rabbitfx\\brightness"): return True
            if "resource\\rabbitfx\\glowmap" in l: return True
            if "resource\\rabbitfx\\fxmap" in l: return True
            if l.startswith("run") and "commandlist\\rabbitfx\\run" in l: return True
            return False

        def build_rabbitfx(indent, cfg):
            glow = cfg.get("glow")
            fx = cfg.get("fx")

            if glow is None and fx is None:
                return []

            block = []
            if glow is not None:
                block.append(f"{indent}$\\rabbitfx\\h = {glow['h']}\n")
                block.append(f"{indent}$\\rabbitfx\\s = {glow['s']}\n")
                block.append(f"{indent}$\\rabbitfx\\v = {glow['v']}\n")
                block.append(f"{indent}$\\rabbitfx\\brightness = {glow['brightness']}\n")
            if glow is not None:
                block.append(f"{indent}Resource\\RabbitFX\\GlowMap = ref ResourceGlow\n")
            if fx is not None:
                block.append(f"{indent}Resource\\RabbitFX\\FXMap = ref ResourceFX\n")
            block.append(f"{indent}run = CommandList\\RabbitFX\\Run\n")
            return block

        def build_resource_sections(cfg):
            glow = cfg.get("glow")
            fx = cfg.get("fx")
            out = []
            if glow is not None:
                out.append("[ResourceGlow]\n")
                out.append(f"filename = Textures/{glow['filename']}\n")
                out.append("\n")
            if fx is not None:
                out.append("[ResourceFX]\n")
                out.append(f"filename = Textures/{fx['filename']}\n")
                out.append("\n")
            return out

        for i, line in enumerate(lines):
            stripped = line.strip()

            m = pattern_header.match(stripped)
            if m:
                comp = int(m.group(1))
                if comp in modifies:
                    new_lines.extend(build_resource_sections(modifies[comp]))
                new_lines.append(line)
                current_comp = comp
                inside = True
                if comp not in inserted:
                    inserted[comp] = False
                continue

            if stripped.startswith("[") and stripped.endswith("]"):
                current_comp = None
                inside = False
                new_lines.append(line)
                continue

            if inside and current_comp in modifies:
                if is_rabbitfx_line(line):
                    continue

                block = modifies[current_comp]

                lower = stripped.lower()
                at_override = lower == "run = commandlistoverridesharedresources"

                if at_override and not inserted[current_comp] and "remove" not in block:
                    indent = line[:len(line) - len(line.lstrip())]
                    new_lines.append(line)
                    new_lines.extend(build_rabbitfx(indent, block))
                    new_lines.append("\n")  # EXACTLY ONE BLANK LINE after RabbitFX
                    inserted[current_comp] = True
                    continue

                if stripped and stripped.lower().startswith(("; draw", "drawindexed")):
                    while len(new_lines) > 0 and new_lines[-1].strip() == "":
                        new_lines.pop()

                new_lines.append(line)
                continue

            new_lines.append(line)

        with open(self.ini_path, "w", encoding="utf-8") as f:
            f.writelines(new_lines)

        self.status_label.config(text="Done. Backup: mod.ini.bak")
        messagebox.showinfo("Success", "Applied.")

def main():
    root = tk.Tk()
    app = RabbitFXTool(root)
    root.mainloop()

if __name__ == "__main__":
    main()
