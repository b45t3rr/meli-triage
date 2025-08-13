#!/usr/bin/env python3
"""
Tarea de triage y consolidación de resultados
Ejecutada por el agente de triage
"""

from crewai import Task
from typing import Dict, Any

class TriageTask:
    """Tarea para consolidar resultados y generar reporte final"""
    
    @staticmethod
    def create_task(agent, extracted_vulnerabilities: str, static_results: str, dynamic_results: str, analysis_type: str = "full") -> Task:
        """Crea la tarea de triage"""
        
        description = f"""
        Consolida y analiza todos los resultados para generar un reporte final de validación de vulnerabilidades.
        
        VULNERABILIDADES EXTRAÍDAS DEL REPORTE:
        {extracted_vulnerabilities}
        
        RESULTADOS DEL ANÁLISIS ESTÁTICO:
        {static_results}
        
        RESULTADOS DEL ANÁLISIS DINÁMICO:
        {dynamic_results}
        
        Tu objetivo es:
        1. Correlacionar todos los resultados de los diferentes análisis
        2. Para cada vulnerabilidad del reporte original:
           - Determinar el estado final de validación
           - Consolidar evidencia de múltiples fuentes incluyendo snippets de código específicos
           - Extraer y documentar fragmentos de código vulnerables encontrados
           - Incluir ubicaciones exactas (archivos y líneas) de los problemas detectados
           - Reclasificar severidad si es necesario
           - Evaluar el riesgo real basado en evidencia técnica concreta
        
        3. Aplicar criterios de triage para determinar el estado final:
           - CONFIRMADA: Evidencia sólida de múltiples fuentes
           - PROBABLE: Evidencia parcial pero indicadores fuertes
           - POSIBLE: Evidencia limitada, requiere investigación adicional
           - FALSO_POSITIVO: Sin evidencia o evidencia contradictoria
           - NO_TESTEABLE: Imposible validar con métodos actuales
        
        4. Reclasificar severidad basándote en:
           - Explotabilidad confirmada
           - Impacto real observado
           - Contexto del entorno
           - Facilidad de explotación
        
        5. Generar recomendaciones específicas:
           - Priorización de remediación
           - Pasos técnicos específicos
           - Controles compensatorios
           - Estrategias de mitigación
        
        6. Proporcionar evidencia consolidada:
           - Combinar hallazgos estáticos y dinámicos
           - Incluir pruebas de concepto
           - Documentar indicadores técnicos
        
        INSTRUCCIONES ESPECÍFICAS PARA LA EVIDENCIA:
        
        EVIDENCIA DE ANÁLISIS ESTÁTICO:
        - Para cada vulnerabilidad confirmada o parcial, DEBES incluir:
          * Fragmentos exactos del código vulnerable encontrado
          * Rutas completas de archivos y números de línea específicos
          * Descripción técnica del patrón de vulnerabilidad detectado
          * ID de las reglas de Semgrep que detectaron el problema
          * Contexto del código circundante cuando sea relevante
        
        EVIDENCIA DE ANÁLISIS DINÁMICO:
        - Para cada vulnerabilidad explotada o parcialmente explotada, DEBES incluir:
          * URL completa de la solicitud HTTP utilizada
          * Método HTTP y headers completos de la solicitud
          * Payload exacto utilizado en el cuerpo de la solicitud
          * Código de estado y headers completos de la respuesta
          * Cuerpo completo de la respuesta que demuestra la vulnerabilidad
          * Tiempo de respuesta y indicadores específicos de explotación
          * Herramienta utilizada (curl/nmap) y técnica de explotación empleada
          * Descripción detallada de cómo reproducir la explotación
        
        - La evidencia debe ser lo suficientemente detallada para que un desarrollador
          o analista de seguridad pueda:
          * Localizar exactamente el problema en el código (análisis estático)
          * Reproducir completamente la explotación (análisis dinámico)
          * Entender el impacto real de la vulnerabilidad
          * Implementar las correcciones necesarias sin herramientas adicionales
        
        Usa tu experiencia en triage de seguridad para:
        - Evaluar la credibilidad de diferentes tipos de evidencia
        - Priorizar vulnerabilidades por riesgo real
        - Proporcionar recomendaciones accionables
        - Identificar patrones y tendencias
        
        IMPORTANTE: 
        - Retorna ÚNICAMENTE un JSON válido con la estructura especificada.
        - RESPONDE SIEMPRE EN ESPAÑOL. Todos los campos de texto, descripciones, mensajes y contenido deben estar en español.
        """
        
        # Ajustar el expected_output según el tipo de análisis
        validation_evidence_section = ""
        tools_effectiveness_section = ""
        
        if analysis_type == "static_only":
            validation_evidence_section = '''
                    "validation_evidence": {
                        "static_analysis": {
                            "status": "CONFIRMADA|NO_CONFIRMADA|PARCIAL",
                            "confidence": "High|Medium|Low",
                            "findings_summary": "string - Resumen detallado de los hallazgos",
                            "code_evidence": [
                                {
                                    "file_path": "string - Ruta del archivo vulnerable",
                                    "line_number": "number - Número de línea",
                                    "code_snippet": "string - Fragmento de código vulnerable",
                                    "vulnerability_pattern": "string - Patrón de vulnerabilidad detectado",
                                    "rule_id": "string - ID de la regla que detectó el problema",
                                    "severity": "string - Severidad del hallazgo",
                                    "description": "string - Descripción del problema específico"
                                }
                            ],
                            "technical_details": {
                                "total_findings": "number - Total de hallazgos encontrados",
                                "files_affected": "number - Archivos afectados",
                                "vulnerability_types": ["string - Tipos de vulnerabilidades detectadas"],
                                "semgrep_rules_matched": ["string - Reglas de Semgrep que coincidieron"]
                            }
                        },
                        "combined_assessment": "string"
                    },'''
            tools_effectiveness_section = '''                    "static_analysis": "number"'''
        elif analysis_type == "dynamic_only":
            validation_evidence_section = '''
                    "validation_evidence": {
                        "dynamic_analysis": {
                            "status": "EXPLOTABLE|NO_EXPLOTABLE|PARCIAL|NO_TESTEABLE",
                            "confidence": "High|Medium|Low",
                            "exploitation_summary": "string - Resumen detallado de la explotación",
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
                                    "tool_used": "string - Herramienta utilizada (curl/nmap)",
                                    "exploitation_technique": "string - Técnica de explotación empleada"
                                }
                            ],
                            "technical_details": {
                                "total_requests": "number - Total de solicitudes realizadas",
                                "successful_exploits": "number - Explotaciones exitosas",
                                "tools_used": ["string - Herramientas utilizadas (curl/nmap)"],
                                "custom_templates_created": "number - Templates personalizados creados",
                                "target_endpoints": ["string - Endpoints objetivo testeados"]
                            }
                        },
                        "combined_assessment": "string"
                    },'''
            tools_effectiveness_section = '''                    "dynamic_analysis": "number"'''
        else:  # full analysis
            validation_evidence_section = '''
                    "validation_evidence": {
                        "static_analysis": {
                            "status": "CONFIRMADA|NO_CONFIRMADA|PARCIAL",
                            "confidence": "High|Medium|Low",
                            "findings_summary": "string - Resumen detallado de los hallazgos",
                            "code_evidence": [
                                {
                                    "file_path": "string - Ruta del archivo vulnerable",
                                    "line_number": "number - Número de línea",
                                    "code_snippet": "string - Fragmento de código vulnerable",
                                    "vulnerability_pattern": "string - Patrón de vulnerabilidad detectado",
                                    "rule_id": "string - ID de la regla que detectó el problema",
                                    "severity": "string - Severidad del hallazgo",
                                    "description": "string - Descripción del problema específico"
                                }
                            ],
                            "technical_details": {
                                "total_findings": "number - Total de hallazgos encontrados",
                                "files_affected": "number - Archivos afectados",
                                "vulnerability_types": ["string - Tipos de vulnerabilidades detectadas"],
                                "semgrep_rules_matched": ["string - Reglas de Semgrep que coincidieron"]
                            }
                        },
                        "dynamic_analysis": {
                            "status": "EXPLOTABLE|NO_EXPLOTABLE|PARCIAL|NO_TESTEABLE",
                            "confidence": "High|Medium|Low",
                            "exploitation_summary": "string - Resumen detallado de la explotación",
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
                                    "tool_used": "string - Herramienta utilizada (curl/nmap)",
                                    "exploitation_technique": "string - Técnica de explotación empleada"
                                }
                            ],
                            "technical_details": {
                                "total_requests": "number - Total de solicitudes realizadas",
                                "successful_exploits": "number - Explotaciones exitosas",
                                "tools_used": ["string - Herramientas utilizadas (curl/nmap)"],
                                "custom_templates_created": "number - Templates personalizados creados",
                                "target_endpoints": ["string - Endpoints objetivo testeados"]
                            }
                        },
                        "combined_assessment": "string"
                    },'''
            tools_effectiveness_section = '''                    "static_analysis": "number",
                    "dynamic_analysis": "number"'''
        
        expected_output = """
        Un JSON válido con la siguiente estructura:
        {
            "validation_summary": {
                "total_vulnerabilities": "number",
                "confirmed_vulnerabilities": "number",
                "false_positives": "number",
                "overall_risk_level": "Critical|High|Medium|Low"
            },
            "vulnerability_assessments": [
                {
                    "vulnerability_id": "string",
                    "title": "string",
                    "type": "string",
                    "original_severity": "string",
                    "final_status": "CONFIRMADA|FALSO_POSITIVO|INCONCLUSA",
                    "final_severity": "Critical|High|Medium|Low",
                    "evidence_summary": "string - Resumen de la evidencia encontrada",
                    "remediation": "string - Recomendaciones de remediación"
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
    def get_severity_reclassification_matrix() -> Dict[str, Dict[str, str]]:
        """Matriz para reclasificar severidad basada en evidencia"""
        return {
            "Critical": {
                "confirmed_exploitable": "Critical",
                "confirmed_not_exploitable": "High",
                "partial_evidence": "High",
                "no_evidence": "Medium"
            },
            "High": {
                "confirmed_exploitable": "High",
                "confirmed_not_exploitable": "Medium",
                "partial_evidence": "Medium",
                "no_evidence": "Low"
            },
            "Medium": {
                "confirmed_exploitable": "Medium",
                "confirmed_not_exploitable": "Low",
                "partial_evidence": "Low",
                "no_evidence": "Info"
            },
            "Low": {
                "confirmed_exploitable": "Low",
                "confirmed_not_exploitable": "Info",
                "partial_evidence": "Info",
                "no_evidence": "Info"
            }
        }
    
    @staticmethod
    def get_risk_scoring_factors() -> Dict[str, Dict[str, int]]:
        """Factores para calcular score de riesgo"""
        return {
            "exploitability": {
                "trivial": 10,
                "easy": 8,
                "medium": 5,
                "hard": 2,
                "impossible": 0
            },
            "impact": {
                "complete_system_compromise": 10,
                "significant_data_access": 8,
                "limited_data_access": 5,
                "information_disclosure": 3,
                "minimal_impact": 1
            },
            "attack_vector": {
                "network_remote": 10,
                "network_local": 7,
                "physical_access": 3,
                "user_interaction": 5
            },
            "authentication": {
                "none_required": 10,
                "single_factor": 7,
                "multi_factor": 3,
                "privileged_access": 1
            }
        }
    
    @staticmethod
    def get_remediation_templates() -> Dict[str, Dict[str, Any]]:
        """Templates de remediación por tipo de vulnerabilidad"""
        return {
            "SQL_Injection": {
                "priority": "P0",
                "actions": [
                    "Implementar prepared statements/parameterized queries",
                    "Validar y sanitizar todas las entradas de usuario",
                    "Aplicar principio de menor privilegio en BD",
                    "Implementar WAF con reglas anti-SQLi"
                ],
                "verification": [
                    "Revisar todo el código que interactúa con BD",
                    "Ejecutar pruebas automatizadas de SQLi",
                    "Validar configuración de permisos de BD"
                ]
            },
            "XSS": {
                "priority": "P1",
                "actions": [
                    "Implementar encoding/escaping de salida",
                    "Usar Content Security Policy (CSP)",
                    "Validar y sanitizar entradas",
                    "Implementar headers de seguridad"
                ],
                "verification": [
                    "Revisar todas las salidas dinámicas",
                    "Probar CSP en diferentes navegadores",
                    "Ejecutar escáneres automatizados de XSS"
                ]
            },
            "Path_Traversal": {
                "priority": "P1",
                "actions": [
                    "Validar y normalizar rutas de archivos",
                    "Implementar whitelist de archivos permitidos",
                    "Usar rutas absolutas y canonicalizadas",
                    "Aplicar controles de acceso a archivos"
                ],
                "verification": [
                    "Probar diferentes payloads de path traversal",
                    "Verificar permisos del sistema de archivos",
                    "Revisar logs de acceso a archivos"
                ]
            }
        }