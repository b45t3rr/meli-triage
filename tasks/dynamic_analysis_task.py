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
        1. ANALIZAR VULNERABILIDADES ESPECÍFICAS:
           - Parsear las vulnerabilidades extraídas del reporte
           - Identificar CWEs, endpoints, parámetros y payloads específicos
           - Correlacionar con resultados del análisis estático si están disponibles
        
        2. CREAR TEMPLATES PERSONALIZADOS DE NUCLEI:
           - NO uses templates genéricos o predefinidos de Nuclei
           - Para CADA vulnerabilidad específica, crea un template YAML personalizado que:
             * Use los endpoints exactos mencionados en el reporte
             * Incluya los parámetros vulnerables identificados
             * Implemente los payloads específicos del tipo de vulnerabilidad
             * Tenga matchers apropiados para detectar la explotación exitosa
        
        3. EJECUTAR ANÁLISIS DINÁMICO DIRIGIDO:
           - Usar ÚNICAMENTE los templates personalizados creados
           - Testear cada endpoint vulnerable con payloads específicos
           - Aplicar técnicas de bypass si es necesario
           - Documentar cada intento de explotación con evidencia HTTP completa
        
        4. VALIDACIÓN DE EXPLOTABILIDAD:
           Para cada vulnerabilidad, determinar:
           - EXPLOTABLE: Confirmada mediante explotación exitosa con evidencia
           - NO_EXPLOTABLE: No se pudo explotar después de intentos dirigidos
           - PARCIAL: Respuesta anómala que indica vulnerabilidad pero sin explotación completa
           - NO_TESTEABLE: No es posible testear dinámicamente (ej: vulnerabilidades de configuración)
        
        5. ENFOQUE DIRIGIDO vs GENÉRICO:
           - Prioriza la creación de templates específicos sobre el uso de templates genéricos
           - Cada template debe ser diseñado para la vulnerabilidad específica reportada
           - Usa la información contextual del reporte para crear pruebas más precisas
        
        7. DOCUMENTAR EVIDENCIA HTTP DETALLADA:
           Para cada intento de explotación, DEBES registrar:
           - URL completa de la solicitud HTTP
           - Método HTTP utilizado (GET, POST, PUT, etc.)
           - Headers completos de la solicitud
           - Cuerpo completo de la solicitud incluyendo el payload
           - Código de estado HTTP de la respuesta
           - Headers completos de la respuesta
           - Cuerpo completo de la respuesta
           - Tiempo de respuesta
           - Indicadores específicos que demuestran la vulnerabilidad
           - Template de Nuclei utilizado
           - Técnica de explotación empleada
        
        Usa tu experiencia en penetration testing para:
        - Crear templates de Nuclei efectivos
        - Interpretar respuestas de la aplicación
        - Identificar indicadores de vulnerabilidades
        - Evitar falsos positivos
        - Capturar evidencia forense completa de las explotaciones
        
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
                        "http_evidence": [
                            {
                                "request_url": "string - URL completa de la solicitud",
                                "request_method": "string - Método HTTP (GET, POST, etc.)",
                                "request_headers": "string - Headers de la solicitud HTTP",
                                "request_body": "string - Cuerpo de la solicitud (payload)",
                                "response_status": "number - Código de estado HTTP",
                                "response_headers": "string - Headers de la respuesta",
                                "response_body": "string - Cuerpo de la respuesta (evidencia)",
                                "response_time": "string - Tiempo de respuesta",
                                "vulnerability_indicator": "string - Indicador específico de vulnerabilidad",
                                "payload_type": "string - Tipo de payload utilizado",
                                "nuclei_template": "string - Template de Nuclei utilizado",
                                "exploitation_technique": "string - Técnica de explotación empleada"
                            }
                        ],
                        "proof_of_concept": "string - Descripción detallada del PoC",
                        "exploitation_steps": ["string - Pasos específicos para reproducir la explotación"]
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