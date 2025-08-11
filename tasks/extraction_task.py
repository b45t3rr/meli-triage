#!/usr/bin/env python3
"""
Tarea de extracción de vulnerabilidades desde PDFs
Ejecutada por el agente extractor
"""

from crewai import Task
from typing import Dict, Any

class ExtractionTask:
    """Tarea para extraer y estructurar vulnerabilidades desde reportes PDF"""
    
    @staticmethod
    def create_task(agent, pdf_path: str) -> Task:
        """Crea la tarea de extracción"""
        
        description = f"""
        Analiza el reporte de vulnerabilidades en PDF ubicado en: {pdf_path}
        
        Tu objetivo es:
        1. Extraer todo el texto del PDF usando la herramienta PDF Extractor
        2. Identificar y catalogar todas las vulnerabilidades mencionadas
        3. Para cada vulnerabilidad encontrada, extraer:
           - Título/nombre de la vulnerabilidad
           - Descripción detallada
           - Severidad (Critical, High, Medium, Low, Info)
           - CWE ID si está disponible, o asignar uno apropiado
           - Categoría OWASP si aplica
           - URL/endpoint afectado
           - Parámetros vulnerables
           - Método HTTP utilizado
           - Evidencia/payload utilizado
           - Recomendaciones de remediación
        
        4. Estandarizar la información en un formato JSON estructurado
        5. Asignar CWEs apropiados basándote en tu conocimiento de seguridad
        6. Clasificar la severidad de manera consistente
        
        Usa tu experiencia en análisis de vulnerabilidades para:
        - Identificar patrones de vulnerabilidades comunes
        - Asignar CWEs precisos basándote en la descripción
        - Normalizar nombres de vulnerabilidades
        - Extraer información técnica relevante
        
        IMPORTANTE: 
        - Retorna ÚNICAMENTE un JSON válido con la estructura especificada.
        - No incluyas texto adicional, explicaciones o comentarios fuera del JSON.
        - RESPONDE SIEMPRE EN ESPAÑOL. Todos los campos de texto, descripciones, mensajes y contenido deben estar en español.
        """
        
        expected_output = """
        Un JSON válido con la siguiente estructura:
        {
            "document_metadata": {
                "title": "string",
                "total_vulnerabilities": "number",
                "extraction_date": "string",
                "source_file": "string"
            },
            "vulnerabilities": [
                {
                    "id": "string (único)",
                    "title": "string",
                    "description": "string",
                    "severity": "Critical|High|Medium|Low|Info",
                    "cwe_id": "string (ej: CWE-89)",
                    "owasp_category": "string",
                    "affected_url": "string",
                    "affected_parameter": "string",
                    "http_method": "string",
                    "evidence": "string",
                    "payload": "string",
                    "impact": "string",
                    "remediation": "string",
                    "references": ["string"]
                }
            ]
        }
        """
        
        return Task(
            description=description,
            expected_output=expected_output,
            agent=agent
        )
    
    @staticmethod
    def get_vulnerability_schema() -> Dict[str, Any]:
        """Retorna el esquema de vulnerabilidad para referencia"""
        return {
            "type": "object",
            "properties": {
                "document_metadata": {
                    "type": "object",
                    "properties": {
                        "title": {"type": "string"},
                        "total_vulnerabilities": {"type": "number"},
                        "extraction_date": {"type": "string"},
                        "source_file": {"type": "string"}
                    },
                    "required": ["title", "total_vulnerabilities", "extraction_date", "source_file"]
                },
                "vulnerabilities": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string"},
                            "title": {"type": "string"},
                            "description": {"type": "string"},
                            "severity": {
                                "type": "string",
                                "enum": ["Critical", "High", "Medium", "Low", "Info"]
                            },
                            "cwe_id": {"type": "string"},
                            "owasp_category": {"type": "string"},
                            "affected_url": {"type": "string"},
                            "affected_parameter": {"type": "string"},
                            "http_method": {"type": "string"},
                            "evidence": {"type": "string"},
                            "payload": {"type": "string"},
                            "impact": {"type": "string"},
                            "remediation": {"type": "string"},
                            "references": {
                                "type": "array",
                                "items": {"type": "string"}
                            }
                        },
                        "required": [
                            "id", "title", "description", "severity", 
                            "cwe_id", "affected_url", "remediation"
                        ]
                    }
                }
            },
            "required": ["document_metadata", "vulnerabilities"]
        }