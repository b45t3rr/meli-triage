#!/usr/bin/env python3
"""
Tarea de análisis dinámico con herramientas personalizadas
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
        
        2. CREAR PRUEBAS PERSONALIZADAS:
- NO uses templates genéricos o predefinidos
           - Para CADA vulnerabilidad específica, crea un template YAML personalizado que:
             * Use los endpoints exactos mencionados en el reporte
             * Incluya los parámetros vulnerables identificados
             * Implemente los payloads específicos del tipo de vulnerabilidad
             * Tenga matchers apropiados para detectar la explotación exitosa
        
        3. EJECUTAR ANÁLISIS DINÁMICO DIRIGIDO:
           - OPCIÓN A: Usar pruebas personalizadas con curl y nmap para vulnerabilidades simples
           - OPCIÓN B: Usar herramienta curl para análisis inteligente de vulnerabilidades complejas
           - Para vulnerabilidades que requieren autenticación, múltiples pasos o contexto específico:
             * Usar analyze_vulnerability_with_curl(vulnerability, extractor_context, static_context) para análisis detallado
             * Pasar el contexto del agente extractor (tecnologías, frameworks, formularios, parámetros)
             * Pasar el contexto del análisis estático (patrones vulnerables, funciones peligrosas, validaciones)
             * Los payloads serán generados dinámicamente por el LLM basándose en este contexto
             * Realizar reconocimiento inicial del servidor
             * Probar múltiples payloads específicos del tipo de vulnerabilidad
             * Analizar respuestas del servidor para detectar indicadores de explotación
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
           - Herramienta utilizada (curl/nmap)
           - Técnica de explotación empleada
        
        Usa tu experiencia en penetration testing para:
        - Crear pruebas dinámicas efectivas
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
            "dynamic_analysis_results": {
                "vulnerability_id": "string",
                "vulnerability_title": "string",
                "vulnerability_type": "string",
                "exploitation_status": "EXPLOITABLE|NOT_EXPLOITABLE|INCONCLUSIVE",
                "confidence_level": "High|Medium|Low",
                "evidence": {
                    "exploitation_proof": "string",
                    "technical_details": "string"
                }
            }
        }
        """
        
        return Task(
            description=description,
            expected_output=expected_output,
            agent=agent
        )
    

    
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