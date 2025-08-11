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
        - Para cada vulnerabilidad confirmada o parcial, DEBES incluir:
          * Fragmentos exactos del código vulnerable encontrado
          * Rutas completas de archivos y números de línea específicos
          * Descripción técnica del patrón de vulnerabilidad detectado
          * ID de las reglas de Semgrep que detectaron el problema
          * Contexto del código circundante cuando sea relevante
        - La evidencia debe ser lo suficientemente detallada para que un desarrollador
          pueda localizar y entender exactamente el problema sin necesidad de
          herramientas adicionales
        
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
                            "status": "string",
                            "evidence": "string",
                            "confidence": "string"
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
                            "status": "string",
                            "evidence": "string",
                            "confidence": "string"
                        },
                        "combined_assessment": "string"
                    },'''
            tools_effectiveness_section = '''                    "static_analysis": "number",
                    "dynamic_analysis": "number"'''
        
        expected_output = f"""
        Un JSON válido con la siguiente estructura:
        {{
            "triage_metadata": {{
                "analysis_date": "string",
                "analyst": "VulnValidation AI System",
                "total_vulnerabilities_processed": "number",
                "validation_methods_used": ["string"],
                "confidence_threshold": "string"
            }},
            "executive_summary": {{
                "total_confirmed": "number",
                "total_probable": "number",
                "total_possible": "number",
                "total_false_positives": "number",
                "total_not_testeable": "number",
                "overall_risk_rating": "Critical|High|Medium|Low",
                "key_findings": ["string"],
                "immediate_actions_required": ["string"]
            }},
            "validated_vulnerabilities": [
                {{
                    "original_id": "string",
                    "title": "string",
                    "final_status": "CONFIRMADA|PROBABLE|POSIBLE|FALSO_POSITIVO|NO_TESTEABLE",
                    "original_severity": "string",
                    "validated_severity": "Critical|High|Medium|Low|Info",
                    "severity_justification": "string",
                    "confidence_score": "number (0-100)",
                    "risk_score": "number (0-10)",
                    "cwe_id": "string",
                    "owasp_category": "string",
{validation_evidence_section}
                    "exploitability_assessment": {{
                        "ease_of_exploitation": "High|Medium|Low",
                        "attack_vector": "string",
                        "prerequisites": ["string"],
                        "proof_of_concept": "string"
                    }},
                    "impact_assessment": {{
                        "confidentiality_impact": "High|Medium|Low|None",
                        "integrity_impact": "High|Medium|Low|None",
                        "availability_impact": "High|Medium|Low|None",
                        "business_impact": "string",
                        "affected_assets": ["string"]
                    }},
                    "remediation": {{
                        "priority": "P0|P1|P2|P3|P4",
                        "estimated_effort": "string",
                        "recommended_actions": ["string"],
                        "compensating_controls": ["string"],
                        "verification_steps": ["string"]
                    }},
                    "references": ["string"]
                }}
            ],
            "risk_analysis": {{
                "threat_landscape": "string",
                "attack_scenarios": [
                    {{
                        "scenario_name": "string",
                        "attack_path": "string",
                        "likelihood": "High|Medium|Low",
                        "impact": "string",
                        "mitigation": "string"
                    }}
                ],
                "compliance_impact": "string",
                "regulatory_considerations": ["string"]
            }},
            "recommendations": {{
                "immediate_actions": [
                    {{
                        "action": "string",
                        "timeline": "string",
                        "responsible_team": "string",
                        "success_criteria": "string"
                    }}
                ],
                "short_term_improvements": ["string"],
                "long_term_strategy": ["string"],
                "security_controls": [
                    {{
                        "control_type": "string",
                        "description": "string",
                        "implementation_priority": "High|Medium|Low"
                    }}
                ]
            }},
            "metrics": {{
                "validation_accuracy": "number",
                "false_positive_rate": "number",
                "coverage_percentage": "number",
                "time_to_validate": "string",
                "tools_effectiveness": {{
{tools_effectiveness_section}
                }}
            }}
        }}
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