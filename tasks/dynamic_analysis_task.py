#!/usr/bin/env python3
"""
Tarea de análisis dinámico con Nuclei
Ejecutada por el agente dinámico
"""

from crewai import Task
from typing import Dict, Any

class DynamicAnalysisTask:
    """Tarea para validar vulnerabilidades mediante análisis dinámico"""
    
    @staticmethod
    def create_task(agent, extracted_vulnerabilities: str, static_analysis_results: str, target_url: str) -> Task:
        """Crea la tarea de análisis dinámico"""
        
        description = f"""
        Valida las vulnerabilidades mediante análisis dinámico contra la aplicación web objetivo.
        
        VULNERABILIDADES EXTRAÍDAS:
        {extracted_vulnerabilities}
        
        RESULTADOS DEL ANÁLISIS ESTÁTICO:
        {static_analysis_results}
        
        TARGET URL: {target_url}
        
        Tu objetivo es:
        1. Analizar las vulnerabilidades extraídas y los resultados del análisis estático
        2. Para cada vulnerabilidad confirmada o parcialmente confirmada:
           - Determinar si es testeable dinámicamente
           - Seleccionar templates de Nuclei apropiados
           - Crear templates personalizados si es necesario
        
        3. Ejecutar análisis dinámico usando la herramienta Nuclei:
           - Usar templates específicos para cada tipo de vulnerabilidad
           - Aplicar payloads dirigidos basados en la evidencia del reporte
           - Testear endpoints específicos mencionados en el reporte
        
        4. Para vulnerabilidades que requieren templates personalizados:
           - Crear templates YAML específicos basados en:
             * URLs/endpoints del reporte
             * Parámetros vulnerables identificados
             * Payloads específicos mencionados
             * Evidencia del análisis estático
        
        5. Correlacionar resultados de Nuclei con vulnerabilidades reportadas:
           - Confirmar explotabilidad
           - Verificar impacto real
           - Documentar evidencia de explotación
        
        6. Para cada vulnerabilidad, determinar:
           - EXPLOTABLE: Confirmada mediante explotación exitosa
           - NO_EXPLOTABLE: No se pudo explotar
           - PARCIAL: Respuesta anómala pero sin explotación completa
           - NO_TESTEABLE: No es posible testear dinámicamente
        
        Usa tu experiencia en penetration testing para:
        - Crear templates de Nuclei efectivos
        - Interpretar respuestas de la aplicación
        - Identificar indicadores de vulnerabilidades
        - Evitar falsos positivos
        
        IMPORTANTE: 
        - Retorna ÚNICAMENTE un JSON válido con la estructura especificada.
        - RESPONDE SIEMPRE EN ESPAÑOL. Todos los campos de texto, descripciones, mensajes y contenido deben estar en español.
        """
        
        expected_output = """
        Un JSON válido con la siguiente estructura:
        {
            "analysis_metadata": {
                "analysis_date": "string",
                "target_url": "string",
                "total_vulnerabilities_tested": "number",
                "nuclei_version": "string",
                "templates_used": ["string"],
                "custom_templates_created": "number"
            },
            "exploitation_results": [
                {
                    "vulnerability_id": "string (del reporte original)",
                    "vulnerability_title": "string",
                    "exploitation_status": "EXPLOTABLE|NO_EXPLOTABLE|PARCIAL|NO_TESTEABLE",
                    "confidence_level": "High|Medium|Low",
                    "nuclei_findings": [
                        {
                            "template_id": "string",
                            "matched_url": "string",
                            "severity": "string",
                            "description": "string",
                            "extracted_data": ["string"],
                            "response_time": "string",
                            "status_code": "number"
                        }
                    ],
                    "exploitation_details": {
                        "payload_used": "string",
                        "request_method": "string",
                        "vulnerable_parameter": "string",
                        "response_indicators": ["string"],
                        "custom_template_used": "boolean"
                    },
                    "evidence": {
                        "request": "string",
                        "response": "string",
                        "proof_of_concept": "string"
                    },
                    "impact_assessment": {
                        "exploitability": "High|Medium|Low",
                        "data_exposure": "string",
                        "system_impact": "string"
                    },
                    "recommendations": "string"
                }
            ],
            "custom_templates": [
                {
                    "template_name": "string",
                    "vulnerability_type": "string",
                    "template_content": "string (YAML)",
                    "creation_reasoning": "string"
                }
            ],
            "summary": {
                "exploitable_vulnerabilities": "number",
                "non_exploitable_vulnerabilities": "number",
                "partial_exploitations": "number",
                "non_testeable": "number",
                "overall_risk_level": "Critical|High|Medium|Low",
                "additional_findings": "string"
            }
        }
        """
        
        return Task(
            description=description,
            expected_output=expected_output,
            agent=agent
        )
    
    @staticmethod
    def get_cwe_to_nuclei_mapping() -> Dict[str, Dict[str, Any]]:
        """Mapeo de CWEs a configuraciones de Nuclei"""
        return {
            "CWE-89": {
                "tags": ["sqli", "injection"],
                "templates": ["sql-injection", "blind-sqli", "error-sqli"],
                "severity": ["critical", "high"],
                "custom_template_needed": True
            },
            "CWE-79": {
                "tags": ["xss", "injection"],
                "templates": ["reflected-xss", "stored-xss", "dom-xss"],
                "severity": ["high", "medium"],
                "custom_template_needed": True
            },
            "CWE-22": {
                "tags": ["lfi", "traversal"],
                "templates": ["path-traversal", "lfi", "directory-traversal"],
                "severity": ["high", "medium"],
                "custom_template_needed": False
            },
            "CWE-78": {
                "tags": ["rce", "injection"],
                "templates": ["command-injection", "rce"],
                "severity": ["critical", "high"],
                "custom_template_needed": True
            },
            "CWE-94": {
                "tags": ["rce", "injection"],
                "templates": ["code-injection", "eval-injection"],
                "severity": ["critical", "high"],
                "custom_template_needed": True
            },
            "CWE-352": {
                "tags": ["csrf"],
                "templates": ["csrf"],
                "severity": ["medium"],
                "custom_template_needed": False
            },
            "CWE-434": {
                "tags": ["upload", "rce"],
                "templates": ["file-upload", "unrestricted-upload"],
                "severity": ["high", "medium"],
                "custom_template_needed": True
            },
            "CWE-200": {
                "tags": ["exposure", "disclosure"],
                "templates": ["info-disclosure", "sensitive-data"],
                "severity": ["medium", "low"],
                "custom_template_needed": False
            }
        }
    
    @staticmethod
    def get_nuclei_template_structure() -> Dict[str, Any]:
        """Estructura base para templates personalizados de Nuclei"""
        return {
            "id": "custom-vulnerability-test",
            "info": {
                "name": "Custom Vulnerability Test",
                "author": "VulnValidation System",
                "severity": "high",
                "description": "Custom template for specific vulnerability validation",
                "tags": ["custom", "validation"]
            },
            "requests": [
                {
                    "method": "GET",
                    "path": ["/{{BaseURL}}"],
                    "headers": {
                        "User-Agent": "VulnValidation/1.0"
                    },
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [200]
                        },
                        {
                            "type": "word",
                            "words": ["error", "exception"],
                            "condition": "or"
                        }
                    ]
                }
            ]
        }
    
    @staticmethod
    def get_payload_encoding_techniques() -> Dict[str, list]:
        """Técnicas de codificación para bypass de WAF"""
        return {
            "url_encoding": ["%27", "%22", "%3C", "%3E"],
            "double_encoding": ["%2527", "%2522"],
            "unicode_encoding": ["\u0027", "\u0022"],
            "html_encoding": ["&#39;", "&#34;", "&lt;", "&gt;"],
            "case_variation": ["UNION", "union", "UnIoN"],
            "comment_insertion": ["/**/", "--", "#"],
            "whitespace_variation": ["\t", "\n", "\r", " "]
        }