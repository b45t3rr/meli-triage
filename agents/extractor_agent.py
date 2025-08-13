#!/usr/bin/env python3
"""
Agente Extractor - Analiza reportes PDF y extrae vulnerabilidades
Utiliza LLM para categorizar y estandarizar vulnerabilidades
"""

from crewai import Agent
from langchain_openai import ChatOpenAI
from typing import Dict, Any
import json
from config.llm_config import create_llm_instance

class ExtractorAgent:
    """Agente especializado en extraer y categorizar vulnerabilidades de reportes PDF"""
    
    def __init__(self, pdf_tool, llm=None):
        self.pdf_tool = pdf_tool
        if llm is None:
            self.llm = create_llm_instance("gpt-4o-mini", temperature=0.1)
        else:
            self.llm = llm
        
        self.agent = Agent(
            role="Especialista en Análisis de Vulnerabilidades",
            goal="Extraer, analizar y categorizar vulnerabilidades de reportes de seguridad en PDF",
            backstory="""
            Eres un experto analista de seguridad con más de 10 años de experiencia en 
            análisis de vulnerabilidades. Tu especialidad es revisar reportes de seguridad 
            y extraer información técnica precisa y completa sobre vulnerabilidades.
            
            Tienes conocimiento profundo de:
            - OWASP Top 10 y metodologías de testing
            - CWE (Common Weakness Enumeration)
            - CVSS scoring y clasificación de severidad
            - Técnicas de análisis estático y dinámico
            - Protocolos HTTP/HTTPS y análisis de tráfico
            - Frameworks de seguridad y mejores prácticas
            - Análisis de código fuente y patrones de vulnerabilidades
            
            Tu misión es extraer ÚNICAMENTE la información técnica que está EXPLÍCITAMENTE 
            documentada en el reporte:
            - Solicitudes HTTP completas con headers (SOLO si están literalmente en el reporte)
            - Respuestas HTTP completas con headers (SOLO si están literalmente en el reporte)
            - Payloads específicos y técnicas de explotación (SOLO si están disponibles)
            - Fragmentos de código vulnerable (SOLO si están mostrados en el reporte)
            - Componentes y versiones afectadas
            - Evidencias visuales y logs de herramientas (SOLO si están disponibles)
            - Impacto técnico detallado
            
            REGLAS ESTRICTAS - CUMPLE EXACTAMENTE:
              1. Para http_responses: SOLO incluye si el texto muestra LITERALMENTE "HTTP/1.1" seguido de headers completos
              2. Si solo dice "Response included FLAG{...}" o "This returned sensitive files" SIN mostrar la respuesta HTTP completa, deja http_responses como array vacío []
              3. NUNCA inventes, reconstruyas o completes respuestas HTTP parciales
              4. SOLO extrae lo que está TEXTUALMENTE presente en el documento
              5. Si no hay payloads específicos mostrados, deja payloads como array vacío []
              6. Si no hay código fuente mostrado, deja vulnerable_code_snippets como array vacío []
              7. Diferencia estrictamente entre "mencionar un resultado" y "mostrar una respuesta HTTP completa"
              8. Cuando tengas dudas, deja el campo como array vacío []
            
            Tu trabajo es fundamental para el proceso de validación, ya que estableces
            la base de conocimiento completa que utilizarán los demás agentes.
            """,
            verbose=True,
            allow_delegation=False,
            llm=self.llm,
            tools=[self.pdf_tool]
        )
    
    def extract_vulnerabilities_schema(self) -> Dict[str, Any]:
        """Define el esquema JSON mejorado para las vulnerabilidades extraídas"""
        return {
            "vulnerabilities": [
                {
                    "id": "string - ID único de la vulnerabilidad",
                    "title": "string - Título de la vulnerabilidad",
                    "description": "string - Descripción detallada técnica",
                    "severity": "string - Critical|High|Medium|Low (respeta la criticidad del reporte)",
                    "cwe_id": "string - CWE ID (ej: CWE-79)",
                    "type": "string - Tipo de vulnerabilidad (IDOR|XSS|SQLi|LFI|SSRF|etc)",
                    "affected_component": "string - Componente, endpoint, función o archivo afectado",
                    "affected_url": "string - URL completa afectada",
                    "http_method": "string - Método HTTP utilizado (GET, POST, etc.)",
                    "detailed_poc": "string - Explicación detallada paso a paso de cómo explotar la vulnerabilidad. Incluye solicitudes y respuestas HTTP completas, payloads específicos, y secuencia de explotación.",
                    "http_requests": "array - Lista de solicitudes HTTP completas incluyendo headers, método, URL y body",
                    "http_responses": "array - Lista de respuestas HTTP completas incluyendo status code, headers y body",
                    "payloads": "array - Lista de payloads específicos utilizados para explotar la vulnerabilidad",
                    "vulnerable_code_snippets": "array - Lista de fragmentos de código vulnerable con contexto",
                    "evidences": "array - Lista de evidencias: screenshots, logs, outputs, code snippets, configuraciones, etc.",
                    "impact": "string - Descripción del impacto técnico y de negocio",
                    "remediation": "string - Recomendaciones específicas de remediación con ejemplos de código si aplica",
                    "references": "array - Referencias externas, CVEs relacionados, documentación"
                }
            ],
            "metadata": {
                "report_title": "string",
                "scan_date": "string",
                "target_info": "string",
                "total_vulnerabilities": "int",
                "credentials": ["string - Credenciales encontradas en el reporte"],
                "report_type": "string - Tipo de reporte (pentest, scan, audit, etc.)",
                "tools_used": "array - Herramientas utilizadas en el análisis"
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
    
    def get_extraction_guidelines(self) -> Dict[str, str]:
        """Guías específicas para extraer información técnica completa"""
        return {
            "http_requests": "Extraer TODAS las solicitudes HTTP como array SOLO si están disponibles en el reporte. Cada elemento debe incluir: método completo, URL completa, headers completos, y body/payload completo. Si no hay requests HTTP, omitir este campo.",
            "http_responses": "Extraer TODAS las respuestas HTTP como array SOLO si están disponibles en el reporte. Cada elemento debe incluir: status code, headers de respuesta completos, y body completo con datos sensibles o errores reveladores. Si no hay responses HTTP, omitir este campo.",
            "payloads": "Documentar TODOS los payloads como array SOLO si están disponibles en el reporte. Incluir: scripts XSS, consultas SQL, comandos de sistema, paths de traversal, etc. Si no hay payloads específicos, omitir este campo.",
            "vulnerable_code_snippets": "OPCIONAL: Extraer fragmentos de código vulnerable como array SOLO si están disponibles en el reporte. Incluir: funciones completas, clases, métodos, configuraciones, con contexto suficiente para entender la vulnerabilidad. Si no hay código vulnerable mostrado, omitir completamente este campo.",
            "components": "Identificar componentes específicos: versiones de software, librerías, frameworks, servicios, puertos",
            "evidences": "Capturar TODAS las evidencias como array SOLO si están disponibles. Incluir: screenshots, logs de herramientas, outputs de comandos, mensajes de error, configuraciones, archivos, URLs, etc. Si no hay evidencias adicionales, omitir este campo.",
            "impact_details": "Describir impacto técnico específico: qué datos se pueden acceder, qué acciones se pueden realizar, escalación posible",
            "remediation_specific": "Proporcionar remediación específica con ejemplos de código, configuraciones, o parches cuando sea posible",
            "optional_fields": "IMPORTANTE: Los campos http_requests, http_responses, payloads, vulnerable_code_snippets y evidences son OPCIONALES. Solo incluirlos si la información está realmente disponible en el reporte. No inventar o generar contenido que no esté presente."
        }