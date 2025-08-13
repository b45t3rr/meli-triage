#!/usr/bin/env python3
"""
Tarea de análisis estático con Semgrep
Ejecutada por el agente estático
"""

from crewai import Task
from typing import Dict, Any

class StaticAnalysisTask:
    """Tarea para validar vulnerabilidades mediante análisis estático"""
    
    @staticmethod
    def create_task(agent, extracted_vulnerabilities: str, source_code_path: str) -> Task:
        """Crea la tarea de análisis estático"""
        
        description = f"""
        Valida las vulnerabilidades extraídas del reporte mediante análisis estático del código fuente.
        
        VULNERABILIDADES EXTRAÍDAS:
        {extracted_vulnerabilities}
        
        CÓDIGO FUENTE A ANALIZAR: {source_code_path}
        
        Tu objetivo es:
        1. Realizar un escaneo genérico completo del código fuente usando Semgrep con config="auto"
        2. Usar el método analyze_vulnerabilities_with_llm para correlacionar inteligentemente los resultados
        3. El LLM debe analizar contextualmente:
           - Tipos de vulnerabilidad similares (ej: path traversal, directory traversal)
           - Ubicaciones de archivos y patrones de código
           - Funciones, métodos y parámetros específicos
           - Evidencia del reporte vs hallazgos de Semgrep
        
        4. Para cada vulnerabilidad del reporte, determinar:
           - CONFIRMADA: Si el LLM encuentra evidencia correlacionada en Semgrep
           - NO_CONFIRMADA: Si el LLM no encuentra evidencia suficiente
           - PROBABLE: Si el LLM encuentra patrones similares o indicios de la vulnerabilidad
           - PARCIAL: Si el LLM encuentra evidencia parcial o incompleta
           - NO_APLICABLE: Si el tipo de vulnerabilidad no es detectable por análisis estático
           
        5. IMPORTANTE: Para vulnerabilidades con status PROBABLE, PARCIAL o CONFIRMADA, 
           SIEMPRE incluir evidencia detallada en el campo 'evidence' con:
           - Archivos específicos donde se encontraron patrones
           - Números de línea exactos
           - Fragmentos de código relevantes
           - Mensajes de las reglas de Semgrep que coincidieron
        
        INSTRUCCIONES ESPECÍFICAS:
        - Primero ejecuta perform_targeted_scan() pasando el path del código fuente Y las vulnerabilidades extraídas
        - Este método generará automáticamente reglas de Semgrep específicas para cada tipo de vulnerabilidad reportada
        - Luego usa analyze_vulnerabilities_with_llm() pasando los resultados de Semgrep y las vulnerabilidades extraídas
        - El LLM debe proporcionar razonamiento detallado para cada correlación
        - Si el LLM no está disponible, usa el método de fallback automáticamente
        - Las reglas dinámicas se crean automáticamente para cualquier tipo de vulnerabilidad reportada: Path Traversal, SQL Injection, SSRF, XSS, IDOR, Command Injection, etc
        
        IMPORTANTE: 
        - Retorna ÚNICAMENTE un JSON válido con la estructura especificada.
        - RESPONDE SIEMPRE EN ESPAÑOL. Todos los campos de texto, descripciones, mensajes y contenido deben estar en español.
        """
        
        expected_output = """
        Un JSON válido con la siguiente estructura:
        {
            "static_analysis_results": {
                "vulnerability_id": "string",
                "vulnerability_title": "string",
                "vulnerability_type": "string",
                "validation_status": "CONFIRMED|NOT_FOUND|PARTIAL|INCONCLUSIVE",
                "confidence_level": "High|Medium|Low",
                "evidence": {
                    "code_snippets": [
                        {
                            "file_path": "string",
                            "line_numbers": "string",
                            "vulnerable_code": "string",
                            "vulnerability_pattern": "string"
                        }
                    ],
                    "analysis_summary": "string - Resumen del análisis realizado"
                }
            }
        }
        """
        
        return Task(
            description=description,
            expected_output=expected_output,
            agent=agent
        )