import subprocess
import sys
import os
import tkinter as tk


def run_script(relative_path):
    python_exe = sys.executable
    script_path = os.path.join(os.path.dirname(__file__), relative_path)
    subprocess.Popen([python_exe, script_path], cwd=os.path.dirname(script_path))


class Launcher:
    def __init__(self, root):
        root.title("WWMI Support Tools Launcher")
        root.geometry("350x200")

        frame = tk.Frame(root)
        frame.pack(expand=True)

        tk.Label(frame, text="Select a tool to run:").pack(pady=15)

        tk.Button(
            frame, text="Toggle Maker", width=25,
            command=lambda: run_script("WWMI_Toggle_Maker/WWMI_Toggle_Maker.py")
        ).pack(pady=5)

        tk.Button(
            frame, text="RabbitFX Maker", width=25,
            command=lambda: run_script("WWMI_Rabbit_Maker/WWMI_Rabbit_Maker.py")
        ).pack(pady=5)

        tk.Button(
            frame, text="Transparency Maker", width=25,
            command=lambda: run_script("WWMI_Transparency_Maker/WWMI_Transparency_Maker.py")
        ).pack(pady=5)


def main():
    root = tk.Tk()
    Launcher(root)
    root.mainloop()


if __name__ == "__main__":
    main()
