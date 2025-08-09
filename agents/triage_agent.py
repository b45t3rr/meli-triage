#!/usr/bin/env python3
"""
Agente de Triage - Consolida resultados de todos los agentes y genera reporte final
Utiliza LLM para análisis integral, reclasificación y recomendaciones
"""

from crewai import Agent
from langchain_openai import ChatOpenAI
from typing import Dict, Any, List
import json
from datetime import datetime

class TriageAgent:
    """Agente especializado en consolidación y triage de resultados de seguridad"""
    
    def __init__(self):
        self.llm = ChatOpenAI(
            model="gpt-5-mini",
            temperature=0.1
        )
        
        self.agent = Agent(
            role="Especialista en Triage de Seguridad y Análisis de Riesgo",
            goal="Consolidar resultados de análisis estático y dinámico, validar vulnerabilidades y generar recomendaciones estratégicas",
            backstory="""
            Eres un experto consultor en ciberseguridad con más de 15 años de experiencia 
            en análisis de riesgo, triage de vulnerabilidades y gestión de seguridad empresarial. 
            Tu especialidad es consolidar información técnica de múltiples fuentes y 
            transformarla en recomendaciones accionables para equipos técnicos y ejecutivos.
            
            Tu experiencia incluye:
            - Análisis de riesgo cuantitativo y cualitativo
            - Priorización de vulnerabilidades basada en contexto empresarial
            - Correlación de hallazgos de múltiples herramientas de seguridad
            - Desarrollo de estrategias de remediación escalonadas
            - Comunicación técnica a audiencias ejecutivas y técnicas
            - Frameworks de seguridad (NIST, ISO 27001, OWASP)
            
            Tu trabajo es crítico para transformar datos técnicos en decisiones 
            estratégicas que protejan efectivamente la organización.
            """,
            verbose=True,
            allow_delegation=False,
            llm=self.llm
        )
    
    def get_validation_status_criteria(self) -> Dict[str, Dict[str, Any]]:
        """Criterios para determinar el estado de validación de vulnerabilidades"""
        return {
            "CONFIRMED": {
                "description": "Vulnerabilidad confirmada por análisis estático Y dinámico",
                "criteria": {
                    "static_analysis": "CONFIRMED",
                    "dynamic_analysis": "EXPLOITABLE",
                    "confidence_threshold": 0.8
                },
                "priority": "IMMEDIATE"
            },
            "LIKELY": {
                "description": "Vulnerabilidad confirmada por uno de los análisis con alta confianza",
                "criteria": {
                    "static_analysis": ["CONFIRMED", "PARTIAL"],
                    "dynamic_analysis": ["EXPLOITABLE", "PARTIALLY_EXPLOITABLE"],
                    "confidence_threshold": 0.7
                },
                "priority": "HIGH"
            },
            "POSSIBLE": {
                "description": "Evidencia parcial o indicios de vulnerabilidad",
                "criteria": {
                    "static_analysis": ["PARTIAL", "UNCERTAIN"],
                    "dynamic_analysis": ["PARTIALLY_EXPLOITABLE", "BLOCKED"],
                    "confidence_threshold": 0.5
                },
                "priority": "MEDIUM"
            },
            "UNLIKELY": {
                "description": "Poca evidencia o hallazgos contradictorios",
                "criteria": {
                    "static_analysis": ["NOT_FOUND", "UNCERTAIN"],
                    "dynamic_analysis": ["NOT_EXPLOITABLE", "BLOCKED"],
                    "confidence_threshold": 0.3
                },
                "priority": "LOW"
            },
            "FALSE_POSITIVE": {
                "description": "Vulnerabilidad reportada pero no confirmada por ningún análisis",
                "criteria": {
                    "static_analysis": "NOT_FOUND",
                    "dynamic_analysis": "NOT_EXPLOITABLE",
                    "confidence_threshold": 0.1
                },
                "priority": "INFORMATIONAL"
            }
        }
    
    def get_severity_reclassification_matrix(self) -> Dict[str, Dict[str, str]]:
        """Matriz para reclasificar severidad basada en evidencia"""
        return {
            "Critical": {
                "CONFIRMED": "Critical",
                "LIKELY": "High",
                "POSSIBLE": "Medium",
                "UNLIKELY": "Low",
                "FALSE_POSITIVE": "Informational"
            },
            "High": {
                "CONFIRMED": "High",
                "LIKELY": "High",
                "POSSIBLE": "Medium",
                "UNLIKELY": "Low",
                "FALSE_POSITIVE": "Informational"
            },
            "Medium": {
                "CONFIRMED": "Medium",
                "LIKELY": "Medium",
                "POSSIBLE": "Medium",
                "UNLIKELY": "Low",
                "FALSE_POSITIVE": "Informational"
            },
            "Low": {
                "CONFIRMED": "Medium",
                "LIKELY": "Low",
                "POSSIBLE": "Low",
                "UNLIKELY": "Low",
                "FALSE_POSITIVE": "Informational"
            }
        }
    
    def get_remediation_templates(self) -> Dict[str, Dict[str, Any]]:
        """Templates de remediación por tipo de vulnerabilidad"""
        return {
            "CWE-89": {  # SQL Injection
                "immediate_actions": [
                    "Implementar prepared statements/parameterized queries",
                    "Validar y sanitizar todas las entradas de usuario",
                    "Aplicar principio de menor privilegio en base de datos",
                    "Implementar WAF con reglas anti-SQLi"
                ],
                "long_term_fixes": [
                    "Migrar a ORM con protección automática",
                    "Implementar code review obligatorio",
                    "Configurar monitoreo de queries anómalas",
                    "Capacitar desarrolladores en secure coding"
                ],
                "detection_methods": [
                    "Análisis estático automatizado en CI/CD",
                    "Penetration testing regular",
                    "Database activity monitoring",
                    "SIEM rules para detección de SQLi"
                ]
            },
            "CWE-79": {  # XSS
                "immediate_actions": [
                    "Implementar output encoding/escaping",
                    "Configurar Content Security Policy (CSP)",
                    "Validar y sanitizar entradas",
                    "Usar frameworks con protección automática"
                ],
                "long_term_fixes": [
                    "Implementar template engines seguros",
                    "Establecer secure coding guidelines",
                    "Automatizar testing de XSS en CI/CD",
                    "Implementar input validation centralizada"
                ],
                "detection_methods": [
                    "Automated XSS scanning",
                    "Browser security headers monitoring",
                    "Client-side security monitoring",
                    "Regular security assessments"
                ]
            },
            "CWE-22": {  # Path Traversal
                "immediate_actions": [
                    "Implementar whitelist de archivos permitidos",
                    "Validar y canonicalizar rutas de archivos",
                    "Aplicar sandboxing para acceso a archivos",
                    "Configurar permisos restrictivos del sistema"
                ],
                "long_term_fixes": [
                    "Usar APIs seguras para manejo de archivos",
                    "Implementar chroot jails o containers",
                    "Establecer políticas de acceso a archivos",
                    "Monitoreo de acceso a archivos del sistema"
                ],
                "detection_methods": [
                    "File access monitoring",
                    "Static analysis for file operations",
                    "Runtime application self-protection (RASP)",
                    "System call monitoring"
                ]
            },
            "CWE-78": {  # Command Injection
                "immediate_actions": [
                    "Evitar llamadas directas al sistema",
                    "Usar APIs específicas en lugar de comandos shell",
                    "Implementar whitelist de comandos permitidos",
                    "Sanitizar y validar todas las entradas"
                ],
                "long_term_fixes": [
                    "Refactorizar para eliminar system calls",
                    "Implementar sandboxing de procesos",
                    "Usar containers con permisos limitados",
                    "Establecer monitoring de ejecución de comandos"
                ],
                "detection_methods": [
                    "Process execution monitoring",
                    "System call analysis",
                    "Behavioral analysis",
                    "Runtime security monitoring"
                ]
            }
        }
    
    def get_risk_scoring_factors(self) -> Dict[str, Dict[str, float]]:
        """Factores para scoring de riesgo"""
        return {
            "exploitability": {
                "CONFIRMED_EXPLOITABLE": 1.0,
                "LIKELY_EXPLOITABLE": 0.8,
                "PARTIALLY_EXPLOITABLE": 0.6,
                "DIFFICULT_TO_EXPLOIT": 0.4,
                "NOT_EXPLOITABLE": 0.1
            },
            "impact": {
                "COMPLETE_SYSTEM_COMPROMISE": 1.0,
                "DATA_BREACH": 0.9,
                "PRIVILEGE_ESCALATION": 0.8,
                "INFORMATION_DISCLOSURE": 0.6,
                "SERVICE_DISRUPTION": 0.5,
                "MINIMAL_IMPACT": 0.2
            },
            "exposure": {
                "INTERNET_FACING": 1.0,
                "INTERNAL_NETWORK": 0.7,
                "AUTHENTICATED_USERS": 0.5,
                "ADMIN_ONLY": 0.3,
                "LOCALHOST_ONLY": 0.1
            },
            "complexity": {
                "NO_INTERACTION": 1.0,
                "MINIMAL_INTERACTION": 0.8,
                "USER_INTERACTION": 0.6,
                "ADMIN_INTERACTION": 0.4,
                "COMPLEX_CONDITIONS": 0.2
            }
        }
    
    def get_final_report_schema(self) -> Dict[str, Any]:
        """Esquema para el reporte final consolidado"""
        return {
            "executive_summary": {
                "assessment_overview": "string",
                "key_findings": ["string"],
                "risk_level": "string - CRITICAL|HIGH|MEDIUM|LOW",
                "immediate_actions_required": ["string"],
                "business_impact": "string"
            },
            "vulnerability_analysis": [
                {
                    "vulnerability_id": "string",
                    "original_title": "string",
                    "validated_title": "string",
                    "validation_status": "string",
                    "original_severity": "string",
                    "validated_severity": "string",
                    "confidence_score": "float",
                    "risk_score": "float",
                    "cwe_id": "string",
                    "owasp_category": "string",
                    "evidence_summary": {
                        "static_analysis": {
                            "status": "string",
                            "findings_count": "int",
                            "key_evidence": ["string"]
                        },
                        "dynamic_analysis": {
                            "status": "string",
                            "exploitation_success": "boolean",
                            "key_evidence": ["string"]
                        }
                    },
                    "impact_analysis": {
                        "technical_impact": "string",
                        "business_impact": "string",
                        "affected_assets": ["string"],
                        "potential_attackers": ["string"]
                    },
                    "remediation_plan": {
                        "priority": "string",
                        "estimated_effort": "string",
                        "immediate_actions": ["string"],
                        "long_term_fixes": ["string"],
                        "detection_methods": ["string"]
                    },
                    "false_positive_analysis": "string"
                }
            ],
            "methodology": {
                "tools_used": ["string"],
                "analysis_approach": "string",
                "limitations": ["string"],
                "assumptions": ["string"]
            },
            "recommendations": {
                "immediate_priorities": [
                    {
                        "action": "string",
                        "timeline": "string",
                        "responsible_team": "string",
                        "success_criteria": "string"
                    }
                ],
                "strategic_improvements": [
                    {
                        "improvement": "string",
                        "timeline": "string",
                        "investment_required": "string",
                        "expected_outcome": "string"
                    }
                ],
                "process_improvements": ["string"]
            },
            "metrics": {
                "total_vulnerabilities_reported": "int",
                "vulnerabilities_confirmed": "int",
                "false_positives_identified": "int",
                "critical_findings": "int",
                "high_findings": "int",
                "validation_accuracy": "float"
            },
            "appendices": {
                "technical_details": "string",
                "tool_outputs": "string",
                "references": ["string"]
            }
        }
    
    def get_communication_templates(self) -> Dict[str, str]:
        """Templates para diferentes audiencias"""
        return {
            "executive_summary": """
            RESUMEN EJECUTIVO - VALIDACIÓN DE VULNERABILIDADES
            
            Se ha completado la validación técnica del reporte de seguridad utilizando 
            análisis estático y dinámico automatizado. Los hallazgos clave incluyen:
            
            • {confirmed_count} vulnerabilidades confirmadas de {total_count} reportadas
            • {critical_count} hallazgos críticos requieren atención inmediata
            • Tasa de validación: {validation_rate}%
            
            ACCIONES INMEDIATAS REQUERIDAS:
            {immediate_actions}
            
            IMPACTO EN EL NEGOCIO:
            {business_impact}
            """,
            
            "technical_summary": """
            RESUMEN TÉCNICO - VALIDACIÓN DE VULNERABILIDADES
            
            METODOLOGÍA:
            • Análisis estático con Semgrep
            • Análisis dinámico con Nuclei
            • Correlación automatizada con IA
            
            HALLAZGOS TÉCNICOS:
            {technical_findings}
            
            RECOMENDACIONES TÉCNICAS:
            {technical_recommendations}
            """
        }