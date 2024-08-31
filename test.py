import tkinter as tk

window = tk.Tk()
window.title("Teste Tkinter")
window.geometry('200x100')

label = tk.Label(window, text="Hello, Tkinter!")
label.pack(pady=20)

window.mainloop()
