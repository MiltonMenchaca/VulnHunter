import os
from datetime import datetime

def generate_html_report(results, output_filename="xss_results.html"):
    """
    Generates an HTML report based on the XSS attack results.

    :param results: List of XSS attack results.
    :param output_filename: Name of the output HTML file.
    """
    try:
        html_content = f"""\ 
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>XSS Report</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    margin: 20px;
                }}
                h1 {{
                    text-align: center;
                    color: #333;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                }}
                th, td {{
                    border: 1px solid #ddd;
                    padding: 8px;
                    text-align: left;
                    vertical-align: top; /* To display content better if <br> is present */
                }}
                th {{
                    background-color: #f4f4f4;
                }}
                .success {{
                    color: green;
                }}
                .warning {{
                    color: orange;
                }}
                .error {{
                    color: red;
                }}
            </style>
        </head>
        <body>
            <h1>XSS Results Report</h1>
            <p>Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            <table>
                <thead>
                    <tr>
                        <th>URL</th>
                        <th>Payload</th>
                        <th>Status</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
        """

        for result in results:
            # Determine the CSS class based on the status
            status_class = (
                "success" if result["status"] == "success"
                else "warning" if result["status"] == "failed"
                else "error"
            )

            # Get the response from the dictionary and convert it to a string
            raw_response = str(result.get("response", "N/A"))

            # Replace conflicting characters
            safe_response = (
                raw_response
                .replace("<", "&lt;")     # Prevent HTML injection
                .replace(">", "&gt;")     # Prevent HTML injection
                .replace("\n", "<br>")    # Show line breaks
            )

            html_content += f"""\ 
                <tr>
                    <td>{result['url']}</td>
                    <td>{result['payload']}</td>
                    <td class="{status_class}">{result['status'].capitalize()}</td>
                    <td>{safe_response}</td>
                </tr>
            """

        html_content += """\
                </tbody>
            </table>
        </body>
        </html>
        """

        # Save the content to the file
        with open(output_filename, "w", encoding="utf-8") as file:
            file.write(html_content)

        print(f"[INFO] HTML file generated: {output_filename}")

    except Exception as e:
        print(f"[ERROR] Could not generate the HTML file: {e}")
