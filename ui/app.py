import tkinter as tk
from ui.main_window import MainWindow

def run():
    root = tk.Tk()
    root.title("DES Analyzer")
    root.geometry("1200x800")
    root.minsize(1100, 750)
    app = MainWindow(root)
    app.pack(fill="both", expand=True)
    root.mainloop()

if __name__ == "__main__":
    run()
