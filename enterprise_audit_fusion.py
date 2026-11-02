#!/usr/bin/env python3
"""
Enterprise Audit & Finding Fusion System v7.0
Inspirado en la metodología de consolidación Big 4.
Procesa hallazgos de auditoría (Financiera, Fiscal, Forense, IT),
elimina duplicados, clasifica severidad y genera entregables finales.
"""

import json
import csv
import hashlib
import argparse
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

# ----------------------------------------------------------------------
# 1. MOTOR DE REGLAS Y MAPEO DE RIESGO (ESTÁNDAR DE TRABAJO DE CAMPO)
# ----------------------------------------------------------------------
SEVERITY_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1
}

def calculate_hash(finding: Dict[str, Any]) -> str:
    """Genera un hash único basado en la condición, causa y área afectada para deduplicación."""
    unique_string = f"{finding.get('area', '')}:{finding.get('condition', '')}:{finding.get('cause', '')}"
    return hashlib.sha256(unique_string.lower().encode('utf-8')).hexdigest()

def normalize_severity(impact: int, probability: int) -> str:
    """Calcula la severidad basada en la matriz de riesgo (Impacto x Probabilidad 1-5)."""
    score = impact * probability
    if score >= 20:
        return "CRITICAL"
    elif score >= 12:
        return "HIGH"
    elif score >= 6:
        return "MEDIUM"
    return "LOW"

# ----------------------------------------------------------------------
# 2. MOTOR DE FUSIÓN Y CONSOLIDACIÓN
# ----------------------------------------------------------------------
class FindingFusionEngine:
    def __init__(self):
        self.raw_findings: List[Dict[str, Any]] = []
        self.fused_findings: Dict[str, Dict[str, Any]] = {}

    def load_json(self, filepath: str):
        """Carga hallazgos desde archivos JSON."""
        path = Path(filepath)
        if path.exists():
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                items = data if isinstance(data, list) else data.get("findings", [])
                self.raw_findings.extend(items)

    def load_csv(self, filepath: str):
        """Carga hallazgos desde archivos CSV."""
        path = Path(filepath)
        if path.exists():
            with open(path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # Convertir campos numéricos
                    row['impact'] = int(row.get('impact', 3))
                    row['probability'] = int(row.get('probability', 3))
                    self.raw_findings.append(row)

    def process_fusion(self):
        """Fusiona, deduplica y categoriza los hallazgos."""
        for item in self.raw_findings:
            h_code = calculate_hash(item)
            severity = normalize_severity(
                int(item.get('impact', 3)),
                int(item.get('probability', 3))
            )
            
            if h_code not in self.fused_findings:
                self.fused_findings[h_code] = {
                    "id": f"AUD-{len(self.fused_findings) + 1:04d}",
                    "hash": h_code,
                    "area": item.get("area", "General"),
                    "title": item.get("title", "Hallazgo Sin Título"),
                    "condition": item.get("condition", ""),
                    "criteria": item.get("criteria", "N/A"),
                    "cause": item.get("cause", "N/A"),
                    "effect": item.get("effect", "N/A"),
                    "recommendation": item.get("recommendation", "N/A"),
                    "financial_impact": float(item.get("financial_impact", 0.0)),
                    "severity": severity,
                    "score": SEVERITY_WEIGHTS[severity],
                    "sources": [item.get("source_file", "Imported")],
                    "instances_count": 1
                }
            else:
                # Fusión: Acumular impacto financiero, sumar ocurrencias y registrar origen
                existing = self.fused_findings[h_code]
                existing["financial_impact"] += float(item.get("financial_impact", 0.0))
                existing["instances_count"] += 1
                source = item.get("source_file", "Imported")
                if source not in existing["sources"]:
                    existing["sources"].append(source)

    def export_summary_json(self, output_path: str):
        """Exporta los hallazgos consolidados a JSON."""
        results = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "total_raw": len(self.raw_findings),
                "total_fused": len(self.fused_findings),
                "total_financial_exposure": sum(f["financial_impact"] for f in self.fused_findings.values())
            },
            "findings": list(self.fused_findings.values())
        }
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

    def export_markdown_report(self, output_path: str):
        """Genera Informe Ejecutivo de Auditoría en formato Markdown."""
        fused_list = sorted(self.fused_findings.values(), key=lambda x: x["score"], reverse=True)
        total_exp = sum(f["financial_impact"] for f in fused_list)
        
        md = f"""# INFORME EJECUTIVO DE AUDITORÍA Y FUSIÓN DE HALLAZGOS
**Fecha de Generación:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Estado:** Consolidado (Single Source of Truth)  
**Exposición Financiera Total Estimada:** ${total_exp:,.2f} USD  

---

## 1. RESUMEN DE HALLAZGOS CONSOLIDADOS
| ID | Área | Título | Severidad | Ocurrencias | Impacto Financiero |
|---|---|---|---|---|---|
"""
        for f in fused_list:
            md += f"| {f['id']} | {f['area']} | {f['title']} | **{f['severity']}** | {f['instances_count']} | ${f['financial_impact']:,.2f} |\n"

        md += "\n---\n\n## 2. DETALLE DE HALLAZGOS CRÍTICOS Y DE ALTO RIESGO\n"
        
        for f in fused_list:
            if f['severity'] in ['CRITICAL', 'HIGH']:
                md += f"""
### [{f['id']}] {f['title']}
- **Área Afectada:** {f['area']}
- **Severidad:** {f['severity']}
- **Condición:** {f['condition']}
- **Criterio / Norma:** {f['criteria']}
- **Causa Raíz:** {f['cause']}
- **Efecto / Riesgo:** {f['effect']}
- **Recomendación Enterprise:** {f['recommendation']}
- **Fuentes Consolidadas:** {', '.join(f['sources'])}
"""
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(md)

# ----------------------------------------------------------------------
# 3. INTERFAZ DE LÍNEA DE COMANDOS (CLI)
# ----------------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enterprise Audit Finding Fusion CLI")
    parser.add_argument("--inputs", nargs="+", help="Archivos de entrada (.json o .csv)", required=True)
    parser.add_argument("--out-json", default="fused_findings.json", help="Ruta de salida JSON")
    parser.add_argument("--out-report", default="AUDIT_REPORT.md", help="Ruta de salida Informe Markdown")
    
    args = parser.parse_args()
    engine = FindingFusionEngine()

    for file_path in args.inputs:
        if file_path.endswith('.json'):
            engine.load_json(file_path)
        elif file_path.endswith('.csv'):
            engine.load_csv(file_path)

    engine.process_fusion()
    engine.export_summary_json(args.out_json)
    engine.export_markdown_report(args.out_report)
    
    print(f"[✔] Fusión completada con éxito.")
    print(f"    - Hallazgos procesados: {len(engine.raw_findings)}")
    print(f"    - Hallazgos únicos fusionados: {len(engine.fused_findings)}")
    print(f"    - JSON consolidado: {args.out_json}")
    print(f"    - Informe Markdown: {args.out_report}")