import json
import csv
from fpdf import FPDF
import os
import datetime
import tkinter.messagebox as messagebox
import html


def export_sql_to_csv(filename, results):
    """
    Exports SQL Injection results to a CSV file.

    :param filename: Name of the CSV file to generate.
    :param results: List of dictionaries with the results.
    """
    if not results:
        messagebox.showwarning("Warning", "There are no results to export to CSV.")
        return

    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            # Write headers based on the keys of the results
            headers = results[0].keys() if results else []
            writer.writerow(headers)
            for entry in results:
                writer.writerow([entry.get(key, "") for key in headers])
        messagebox.showinfo("Success", f"SQL results exported to {os.path.abspath(filename)}")
    except Exception as e:
        messagebox.showerror("Error", f"Could not export to CSV: {e}")


def export_sql_to_json(filename, results):
    """
    Exports SQL Injection results to a JSON file.

    :param filename: Name of the JSON file to generate.
    :param results: List of dictionaries with the results.
    """
    if not results:
        messagebox.showwarning("Warning", "There are no results to export to JSON.")
        return

    try:
        with open(filename, 'w', encoding='utf-8') as jsonfile:
            json.dump(results, jsonfile, indent=4, ensure_ascii=False)
        messagebox.showinfo("Success", f"SQL results exported to {os.path.abspath(filename)}")
    except Exception as e:
        messagebox.showerror("Error", f"Could not export to JSON: {e}")


def export_sql_to_pdf(filename, results):
    """
    Exports SQL Injection results to a PDF file.

    :param filename: Name of the PDF file to generate.
    :param results: List of dictionaries with the results.
    """
    if not results:
        messagebox.showwarning("Warning", "There are no results to export to PDF.")
        return

    try:
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", 'B', 16)
        pdf.cell(0, 10, "SQL Injection Report", ln=True, align="C")
        pdf.set_font("Arial", size=12)
        pdf.cell(0, 10, f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align="C")
        pdf.ln(10)  # Line break

        # Determine all unique keys in the results
        keys = results[0].keys() if results else []

        # Headers
        pdf.set_font("Arial", 'B', 12)
        for key in keys:
            pdf.cell(40, 10, key.capitalize(), border=1, align='C')
        pdf.ln()

        # Rows
        pdf.set_font("Arial", size=12)
        for entry in results:
            for key in keys:
                value = entry.get(key, "N/A")
                # Shorten the value if it is too long
                if isinstance(value, str) and len(value) > 40:
                    value = value[:37] + "..."
                pdf.cell(40, 10, str(value), border=1)
            pdf.ln()

        pdf.output(filename)
        messagebox.showinfo("Success", f"PDF report generated: {os.path.abspath(filename)}")
    except Exception as e:
        messagebox.showerror("Error", f"Could not export to PDF: {e}")


def export_results(format_type, filename, results):
    """
    Exports results in the specified format ('txt', 'json', 'html').

    :param format_type: Format type ('txt', 'json', 'html').
    :param filename: Output file name.
    :param results: List of dictionaries with the results.
    """
    if not results:
        messagebox.showwarning("Warning", "There are no results to export.")
        return

    try:
        if format_type == "txt":
            content = "\n".join(
                [", ".join([f"{key}: {value}" for key, value in entry.items()]) for entry in results]
            )
            with open(filename, "w", encoding="utf-8") as file:
                file.write(content)

        elif format_type == "json":
            with open(filename, "w", encoding="utf-8") as file:
                json.dump(results, file, indent=4, ensure_ascii=False)

        elif format_type == "html":
            # Generate HTML content
            keys = results[0].keys() if results else []
            html_content = "<html><body><h1>Scan Results</h1><table border='1'><tr>"
            html_content += "".join(f"<th>{html.escape(key.capitalize())}</th>" for key in keys)
            html_content += "</tr>"
            for entry in results:
                html_content += "<tr>"
                for key in keys:
                    value = entry.get(key, "N/A")
                    html_content += f"<td>{html.escape(str(value))}</td>"
                html_content += "</tr>"
            html_content += "</table></body></html>"

            with open(filename, "w", encoding="utf-8") as file:
                file.write(html_content)

        else:
            messagebox.showerror("Error", f"Unsupported format: {format_type}")
            return

        messagebox.showinfo("Success", f"Results exported to {os.path.abspath(filename)}")
    except Exception as e:
        messagebox.showerror("Error", f"Could not export to {format_type.upper()}: {e}")
