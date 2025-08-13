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
        3. Para cada vulnerabilidad encontrada, extraer TODA la información técnica disponible:
           - Título/nombre de la vulnerabilidad
           - Descripción técnica detallada
           - Severidad (Critical, High, Medium, Low, Info)
           - CWE ID si está disponible, o asignar uno apropiado
           - Categoría OWASP si aplica
           - URL/endpoint completo afectado
           - Parámetros específicos vulnerables
           - Método HTTP utilizado (GET, POST, PUT, etc.)
           - MÚLTIPLES solicitudes HTTP COMPLETAS (SOLO si están disponibles en el reporte)
           - MÚLTIPLES respuestas HTTP COMPLETAS (SOLO si están disponibles en el reporte)
           - MÚLTIPLES payloads específicos utilizados (SOLO si están disponibles)
           - MÚLTIPLES fragmentos de código vulnerable con contexto (SOLO si están disponibles)
           - Componentes y versiones afectadas
           - MÚLTIPLES evidencias adicionales de diferentes tipos (SOLO si están disponibles)
           - Detalle de explotación paso a paso con información técnica completa
           - Impacto técnico y de negocio
           - Recomendaciones específicas de remediación con ejemplos
           - Referencias externas y CVEs relacionados
        
        4. Estandarizar la información en un formato JSON estructurado
        5. Asignar CWEs apropiados basándote en tu conocimiento de seguridad
        6. Clasificar la severidad de manera consistente
        
        Usa tu experiencia en análisis de vulnerabilidades para:
        - Identificar patrones de vulnerabilidades comunes
        - Asignar CWEs precisos basándote en la descripción
        - Normalizar nombres de vulnerabilidades
        - Extraer TODA la información técnica disponible en el reporte
        - Capturar solicitudes y respuestas HTTP completas
        - Identificar payloads específicos y técnicas de explotación
        - Extraer fragmentos de código vulnerable
        - Documentar componentes y versiones afectadas
        - Preservar evidencias visuales y logs de herramientas
        
        IMPORTANTE: 
        - Retorna ÚNICAMENTE un JSON válido con la estructura especificada.
        - No incluyas texto adicional, explicaciones o comentarios fuera del JSON.
        - RESPONDE SIEMPRE EN ESPAÑOL. Todos los campos de texto, descripciones, mensajes y contenido deben estar en español.
        - NO INVENTES información que no esté en el reporte. Los campos http_requests, http_responses, payloads, vulnerable_code_snippets y evidences son OPCIONALES.
        - SOLO incluye estos campos opcionales si la información está realmente presente y documentada en el reporte PDF.
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
                    "type": "string (IDOR|XSS|SQLi|LFI|SSRF|etc)",
                    "affected_url": "string",
                    "http_method": "string",
                    "detailed_poc": "string - Explicación detallada paso a paso de cómo explotar la vulnerabilidad. Incluye solicitudes y respuestas HTTP completas, payloads específicos, y secuencia de explotación.",
                    "http_requests": ["Lista de solicitudes HTTP completas con headers, método, URL y body"],
                     "http_responses": ["Lista de respuestas HTTP completas con status code, headers y body"],
                     "payloads": ["Lista de payloads específicos utilizados"],
                     "vulnerable_code_snippets": ["Lista de fragmentos de código vulnerable con contexto"],
                     "evidences": ["Lista de evidencias: screenshots, logs, outputs, code snippets, configuraciones"],
                    "impact": "string - Impacto técnico y de negocio",
                    "remediation": "string - Recomendaciones específicas con ejemplos",
                    "references": "array - Referencias externas y CVEs relacionados"
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
                            "type": {"type": "string"},
                            "affected_url": {"type": "string"},
                            "affected_parameter": {"type": "string"},
                            "http_method": {"type": "string"},
                            "detailed_poc": {"type": "string"},
                             "http_requests": {
                                 "type": "array",
                                 "items": {"type": "string"}
                             },
                             "http_responses": {
                                 "type": "array",
                                 "items": {"type": "string"}
                             },
                             "payloads": {
                                 "type": "array",
                                 "items": {"type": "string"}
                             },
                             "vulnerable_code_snippets": {
                                 "type": "array",
                                 "items": {"type": "string"}
                             },
                             "evidences": {
                                 "type": "array",
                                 "items": {"type": "string"}
                             },
                            "impact": {"type": "string"},
                            "remediation": {"type": "string"},
                            "references": {
                                "type": "array",
                                "items": {"type": "string"}
                            }
                        },
                        "required": [
                            "id", "title", "description", "severity", 
                            "cwe_id", "type", "affected_url", "remediation"
                        ]
                    }
                }
            },
            "required": ["document_metadata", "vulnerabilities"]
        }