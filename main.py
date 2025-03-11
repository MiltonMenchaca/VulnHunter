import sys
import logging
import os
from src.ui.theme import apply_theme
from src.ui.vulnhunter_app import VulnHunterApp

def main():
    # Asegurar que el directorio de logs existe
    os.makedirs('logs', exist_ok=True)
    
    # Configurar logging
    logging.basicConfig(
        filename='logs/vulnhunter.log',
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Aplicar tema
    apply_theme()

    # Iniciar aplicación
    try:
        app = VulnHunterApp()
        app.mainloop()
    except Exception as e:
        logging.error(f"Error al iniciar la aplicación: {e}", exc_info=True)
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
