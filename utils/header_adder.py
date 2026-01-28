import os

HEADER_TEXT = """
 * Nom de l'application : CyberConfiance
 * Description : {description}
 * Produit de : MOA Digital Agency, www.myoneart.com
 * Fait par : Aisance KALONJI, www.aisancekalonji.com
 * Auditer par : La CyberConfiance, www.cyberconfiance.com
"""

def get_comment_style(ext):
    if ext == '.py':
        return ('"""', '"""')
    elif ext in ['.html', '.xml']:
        return ('<!--', '-->')
    elif ext in ['.js', '.css']:
        return ('/*', '*/')
    return None

def add_header(filepath):
    _, ext = os.path.splitext(filepath)
    style = get_comment_style(ext)
    if not style:
        return

    start_tag, end_tag = style
    filename = os.path.basename(filepath)
    description = f"Fichier {filename} du projet CyberConfiance"

    header_content = f"{start_tag}{HEADER_TEXT.format(description=description)}\n{end_tag}\n"

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        if "Auditer par : La CyberConfiance" in content:
            # print(f"Skipping {filepath} (already has header)")
            return

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(header_content + "\n" + content)
        print(f"Updated {filepath}")
    except Exception as e:
        print(f"Failed to update {filepath}: {e}")

def main():
    skip_dirs = {'.git', '__pycache__', 'venv', '.jules', 'migrations'}
    for root, dirs, files in os.walk('.'):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for file in files:
            if file == 'header_adder.py': continue
            filepath = os.path.join(root, file)
            add_header(filepath)

if __name__ == '__main__':
    main()
