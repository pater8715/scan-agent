#!/usr/bin/env python3
"""
update_catalog.py — Actualiza el catálogo de recomendaciones con instrucciones en lenguaje natural.

El catálogo se encuentra en: data/recommendations_catalog.json

Uso:
    python scripts/update_catalog.py "actualiza FTP con CVEs de 2025"
    python scripts/update_catalog.py "añade el puerto 5000 como riesgo medio"
    python scripts/update_catalog.py "mejora las recomendaciones de la cabecera CSP"
    python scripts/update_catalog.py "agrega mongodb a sensitive_paths como CRITICAL"

Requiere:
    pip install anthropic

Variables de entorno:
    ANTHROPIC_API_KEY — clave API de Anthropic (requerida)
"""

import sys
import json
import re
import shutil
from pathlib import Path
from datetime import date

try:
    import anthropic
except ImportError:
    print("Error: el paquete 'anthropic' no está instalado.")
    print("Instálalo con:  pip install anthropic")
    sys.exit(1)

PROJECT_ROOT = Path(__file__).parent.parent
CATALOG_PATH = PROJECT_ROOT / "data" / "recommendations_catalog.json"
MODEL = "claude-opus-4-7"


def load_catalog() -> dict:
    if not CATALOG_PATH.exists():
        print(f"Error: catálogo no encontrado en {CATALOG_PATH}")
        sys.exit(1)
    with open(CATALOG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def backup_catalog():
    backup = CATALOG_PATH.with_suffix(".json.bak")
    shutil.copy2(CATALOG_PATH, backup)
    print(f"  Backup guardado en: {backup.name}")


def save_catalog(catalog: dict):
    catalog["last_updated"] = str(date.today())
    with open(CATALOG_PATH, "w", encoding="utf-8") as f:
        json.dump(catalog, f, ensure_ascii=False, indent=2)
    print(f"  Catálogo guardado: {CATALOG_PATH}")


def deep_merge(base: dict, updates: dict) -> dict:
    """Fusiona recursivamente 'updates' en 'base' sin eliminar claves existentes."""
    result = dict(base)
    for key, value in updates.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        elif key in result and isinstance(result[key], list) and isinstance(value, list):
            # Para listas: reemplazar si tiene contenido, mantener si está vacía
            result[key] = value if value else result[key]
        else:
            result[key] = value
    return result


def apply_changes(catalog: dict, changes: dict) -> tuple[dict, list]:
    """Aplica los cambios al catálogo, retorna (catalog_actualizado, secciones_modificadas)."""
    sections_updated = []
    for section, new_content in changes.items():
        if section == "last_updated":
            continue
        if isinstance(new_content, dict) and section in catalog and isinstance(catalog[section], dict):
            catalog[section] = deep_merge(catalog[section], new_content)
        elif isinstance(new_content, list) and section in catalog and isinstance(catalog[section], list):
            catalog[section] = new_content if new_content else catalog[section]
        else:
            catalog[section] = new_content
        sections_updated.append(section)
    return catalog, sections_updated


def call_claude(instruction: str, catalog: dict) -> dict:
    client = anthropic.Anthropic()

    catalog_str = json.dumps(catalog, ensure_ascii=False, indent=2)

    system_prompt = (
        "Eres un experto en ciberseguridad que mantiene un catálogo de recomendaciones "
        "de seguridad para un escáner de vulnerabilidades. Tu trabajo es actualizar el "
        "catálogo según las instrucciones del usuario, manteniendo el formato y estructura "
        "existente. Respondes siempre en español. Las recomendaciones deben ser específicas, "
        "accionables y orientadas a equipos de desarrollo y operaciones."
    )

    user_prompt = f"""El catálogo actual es:
```json
{catalog_str}
```

Instrucción: {instruction}

Aplica la instrucción al catálogo. Devuelve ÚNICAMENTE un bloque JSON con las secciones \
que necesitan modificación (no el catálogo completo si solo cambió una parte).

Formato de respuesta:
```json
{{
  "sections_updated": ["nombre_seccion1"],
  "changes": {{
    "nombre_seccion1": {{ ...contenido actualizado COMPLETO de esa sección... }}
  }}
}}
```

Reglas:
- Mantén el mismo esquema y tipos de datos del catálogo
- No elimines entradas existentes a menos que la instrucción lo indique explícitamente
- Puedes añadir, modificar o enriquecer entradas
- Las recomendaciones deben ser concretas, accionables y en español
- Para ports: mantén los campos "risk_level", "description", "recommendations", "cves"
- Para security_headers: mantén "severity", "title", "description", "recommendation", "notes"
- Para sensitive_paths: mantén "severity" y "recommendations"
- Si añades CVEs, inclúyelos como lista de strings en el campo "cves"
- Usa severidades válidas: CRITICAL, HIGH, MEDIUM, LOW, INFO
- Si la instrucción menciona añadir un puerto nuevo, inclúyelo con formato de número como string (ej: "5000")
"""

    print(f"  Consultando {MODEL}...")
    message = client.messages.create(
        model=MODEL,
        max_tokens=8192,
        system=system_prompt,
        messages=[{"role": "user", "content": user_prompt}]
    )

    response_text = message.content[0].text

    # Extraer JSON del bloque de código
    json_match = re.search(r'```json\s*(.*?)\s*```', response_text, re.DOTALL)
    if json_match:
        raw_json = json_match.group(1)
    else:
        # Intentar parsear directamente si no hay bloque de código
        raw_json = response_text.strip()

    try:
        response_data = json.loads(raw_json)
    except json.JSONDecodeError as e:
        print(f"\nError: La respuesta de Claude no es JSON válido: {e}")
        print("Respuesta recibida:")
        print(response_text[:500])
        sys.exit(1)

    return response_data


def preview_changes(changes: dict, catalog: dict):
    """Muestra un resumen de los cambios antes de aplicarlos."""
    print("\nCambios a aplicar:")
    for section, content in changes.items():
        if section == "last_updated":
            continue
        existing = catalog.get(section, {})
        if isinstance(content, dict) and isinstance(existing, dict):
            added = [k for k in content if k not in existing]
            modified = [k for k in content if k in existing and content[k] != existing[k]]
            if added:
                print(f"  [{section}] Nuevas entradas: {', '.join(str(k) for k in added)}")
            if modified:
                print(f"  [{section}] Modificadas: {', '.join(str(k) for k in modified)}")
        elif isinstance(content, list):
            print(f"  [{section}] Lista reemplazada ({len(content)} elementos)")
        else:
            print(f"  [{section}] Valor actualizado")


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)

    instruction = " ".join(sys.argv[1:])
    print(f"\nInstrucción: {instruction}")

    catalog = load_catalog()
    print(
        f"Catálogo cargado — versión {catalog.get('version', '?')}, "
        f"última actualización: {catalog.get('last_updated', '?')}"
    )

    response = call_claude(instruction, catalog)

    changes = response.get("changes", {})
    sections_reported = response.get("sections_updated", list(changes.keys()))

    if not changes:
        print("\nClaude no devolvió cambios para aplicar.")
        sys.exit(0)

    preview_changes(changes, catalog)

    # Confirmar antes de escribir
    print()
    confirm = input("¿Aplicar estos cambios? [s/N]: ").strip().lower()
    if confirm not in ("s", "si", "sí", "y", "yes"):
        print("Cancelado. No se realizaron cambios.")
        sys.exit(0)

    backup_catalog()
    catalog, applied_sections = apply_changes(catalog, changes)
    save_catalog(catalog)

    print(f"\nSecciones actualizadas: {', '.join(applied_sections)}")
    print("Listo.")


if __name__ == "__main__":
    main()
