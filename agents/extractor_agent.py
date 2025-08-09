#!/usr/bin/env python3
"""
Agente Extractor - Analiza reportes PDF y extrae vulnerabilidades
Utiliza LLM para categorizar y estandarizar vulnerabilidades
"""

from crewai import Agent
from langchain_openai import ChatOpenAI
from typing import Dict, Any
import json

class ExtractorAgent:
    """Agente especializado en extraer y categorizar vulnerabilidades de reportes PDF"""
    
    def __init__(self, pdf_tool):
        self.pdf_tool = pdf_tool
        self.llm = ChatOpenAI(
            model="gpt-5-mini",
            temperature=0.1
        )
        
        self.agent = Agent(
            role="Especialista en Análisis de Vulnerabilidades",
            goal="Extraer, analizar y categorizar vulnerabilidades de reportes de seguridad en PDF",
            backstory="""
            Eres un experto analista de seguridad con más de 10 años de experiencia en 
            análisis de vulnerabilidades. Tu especialidad es revisar reportes de seguridad 
            y extraer información técnica precisa sobre vulnerabilidades.
            
            Tienes conocimiento profundo de:
            - OWASP Top 10 y metodologías de testing
            - CWE (Common Weakness Enumeration)
            - CVSS scoring y clasificación de severidad
            - Técnicas de análisis estático y dinámico
            - Frameworks de seguridad y mejores prácticas
            
            Tu trabajo es fundamental para el proceso de validación, ya que estableces
            la base de conocimiento que utilizarán los demás agentes.
            """,
            verbose=True,
            allow_delegation=False,
            llm=self.llm,
            tools=[self.pdf_tool]
        )
    
    def extract_vulnerabilities_schema(self) -> Dict[str, Any]:
        """Define el esquema JSON para las vulnerabilidades extraídas"""
        return {
            "vulnerabilities": [
                {
                    "id": "string - ID único de la vulnerabilidad",
                    "title": "string - Título de la vulnerabilidad",
                    "description": "string - Descripción detallada",
                    "severity": "string - Critical|High|Medium|Low (respeta la criticidad del reporte, si no se especifica, asume la criticidad segun la descripción)",
                    "cwe_id": "string - CWE ID (ej: CWE-79)",
                    "category": "string - Categoría OWASP o tipo",
                    "affected_components": [
                        {
                            "type": "string - file|url|parameter|function",
                            "location": "string - ubicación específica",
                            "details": "string - detalles adicionales"
                        }
                    ],
                    "technical_details": {
                        "attack_vector": "string - vector de ataque",
                        "payload_example": "string - ejemplo de payload",
                        "evidence": "string - evidencia del reporte"
                    },
                    "cvss_score": "float - puntuación CVSS si disponible",
                    "references": ["string - referencias adicionales"],
                    "remediation_hint": "string - pista de remediación del reporte"
                }
            ],
            "metadata": {
                "report_title": "string",
                "scan_date": "string",
                "target_info": "string",
                "total_vulnerabilities": "int"
            }
        }
    

    def get_severity_guidelines(self) -> Dict[str, str]:
        """Guías para asignar severidad basada en impacto"""
        return {
            "Critical": "Vulnerabilidades que permiten compromiso completo del sistema, ejecución remota de código, o acceso administrativo",
            "High": "Vulnerabilidades que permiten acceso no autorizado a datos sensibles, escalación de privilegios, o bypass de controles de seguridad",
            "Medium": "Vulnerabilidades que permiten acceso limitado a información o funcionalidad, o que requieren interacción del usuario",
            "Low": "Vulnerabilidades que proporcionan información limitada o requieren condiciones específicas para ser explotadas"
        }