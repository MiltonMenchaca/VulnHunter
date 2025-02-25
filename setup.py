

from setuptools import setup, find_packages

setup(
    name="vulnhunter",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "requests",
        "bs4",
        "jinja2",
        "reportlab",
        "lxml",
        "python-nmap",
        "tqdm",
        "cryptography",
        "pdfkit",
        "whois",
        "dnspython",
        "customtkinter",
        "pillow",
        "pyyaml"
    ],
    entry_points={
        'console_scripts': [
            # Apunta a la función `main()` definida en main.py (raíz)
            'vulnhunter=main:main',
        ],
    },
    author="Milton" ,
    description="Herramienta avanzada de ciberseguridad para evaluación de vulnerabilidades",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    python_requires=">=3.8",
)
