import sys
import logging
from src.ui.theme import apply_theme

from src.ui.vulnhunter_app import VulnHunterApp

def main():
    apply_theme()

    app = VulnHunterApp()
    app.mainloop()

if __name__ == "__main__":
    main()
