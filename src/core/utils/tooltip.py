"""
Class to create tooltips for widgets
"""

import tkinter as tk

class ToolTip:
    """
    Creates a tooltip for a given widget.
    """
    
    def __init__(self, widget, text='widget info'):
        self.wait_time = 500  # milliseconds
        self.wrap_length = 180  # pixels
        self.widget = widget
        self.text = text
        self.widget.bind('<Enter>', self.enter)
        self.widget.bind('<Leave>', self.leave)
        self.widget.bind('<ButtonPress>', self.leave)
        self.id = None
        self.tw = None

    def enter(self, event=None):
        """Starts the process of showing the tooltip."""
        self.schedule()

    def leave(self, event=None):
        """Hides the tooltip."""
        self.unschedule()
        self.hidetip()

    def schedule(self):
        """Schedules the tooltip to appear."""
        self.unschedule()
        self.id = self.widget.after(self.wait_time, self.showtip)

    def unschedule(self):
        """Cancels the scheduled appearance of the tooltip."""
        id = self.id
        self.id = None
        if id:
            self.widget.after_cancel(id)

    def showtip(self, event=None):
        """
        Displays the tooltip with the specified text.
        """
        x = y = 0
        x, y, cx, cy = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 20
        
        # Create tooltip window
        self.tw = tk.Toplevel(self.widget)
        
        # Remove window decorations
        self.tw.wm_overrideredirect(True)
        self.tw.wm_geometry(f"+{x}+{y}")
        
        # Create label
        label = tk.Label(
            self.tw,
            text=self.text,
            justify='left',
            background="#ffffe0",
            relief='solid',
            borderwidth=1,
            wraplength=self.wrap_length
        )
        label.pack(ipadx=1)

    def hidetip(self):
        """
        Destroys the tooltip window.
        """
        tw = self.tw
        self.tw = None
        if tw:
            tw.destroy()
