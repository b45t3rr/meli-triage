#!/usr/bin/env python3
"""
Agente Dinámico con Arquitectura ReAct (Reasoning + Action)
Valida vulnerabilidades usando análisis dinámico adaptativo
"""

from crewai import Agent
from langchain_openai import ChatOpenAI
from typing import Dict, Any, List, Optional
import json
import time
import logging
from config.llm_config import create_llm_instance
from tools.generic_linux_command_tool import GenericLinuxCommandTool

class DynamicAgent:
    """Agente dinámico con arquitectura ReAct para testing de vulnerabilidades"""
    
    def __init__(self, llm=None):
        self.linux_tool = GenericLinuxCommandTool()
        self.logger = logging.getLogger(self.__class__.__name__)
        
        if llm is None:
            self.llm = create_llm_instance("gpt-4o-mini", temperature=0.1)
        else:
            self.llm = llm
        
        self.agent = Agent(
            role="Especialista en Análisis Dinámico con Arquitectura ReAct",
            goal="Validar vulnerabilidades mediante análisis dinámico adaptativo usando razonamiento y acciones iterativas",
            backstory="""
            Eres un experto en penetration testing que utiliza la metodología ReAct (Reasoning + Action)
            para validar vulnerabilidades de forma adaptativa. Tu enfoque es completamente dinámico:
            
            IMPORTANTE: Ejecutas análisis dinámico usando metodología ReAct:
            1. Razonas sobre cada vulnerabilidad individualmente
            2. Planificas acciones específicas de testing
            3. Ejecutas comandos Linux (curl, nmap, etc.)
            4. Observas y evalúas los resultados
            5. Adaptas tu estrategia basándote en los hallazgos
            6. Iteras hasta obtener evidencia concluyente (máximo 8 iteraciones)
            
            - Analizas cada vulnerabilidad individualmente con múltiples intentos
            - Razonas sobre la mejor estrategia de testing basándote en el contexto
            - Ten en cuenta credenciales si estan disponibles
            - Ejecutas acciones específicas usando herramientas Linux
            - Evalúas los resultados y adaptas tu estrategia
            - Iteras hasta obtener evidencia concluyente (máximo 8 iteraciones por vulnerabilidad)
            
            No usas patrones predefinidos ni técnicas hardcodeadas. Todo tu conocimiento
            se aplica dinámicamente según el contexto específico de cada vulnerabilidad.
            
            Herramientas disponibles: curl, nmap, wget, nc, ping, dig y otros comandos Linux básicos.
            """,
            verbose=True,
            allow_delegation=False,
            llm=self.llm,
            tools=[]
        )
        
        pass  # El agente está configurado para usar ReAct cuando se llame analyze_vulnerabilities directamente
    
    def analyze_vulnerabilities(self, extractor_data: Dict[str, Any], 
                              static_data: Dict[str, Any], 
                              target_url: str) -> Dict[str, Any]:
        """Analiza vulnerabilidades usando arquitectura ReAct"""
        
        # Extraer vulnerabilidades de los datos del extractor
        vulnerabilities = self._extract_vulnerabilities_from_data(extractor_data, static_data)
        
        results = {
            "analysis_metadata": {
                "analysis_date": time.strftime("%Y-%m-%d %H:%M:%S"),
                "target_url": target_url,
                "methodology": "ReAct (Reasoning + Action)",
                "total_vulnerabilities": len(vulnerabilities)
            },
            "vulnerability_validations": []
        }
        
        # Verificar si hay vulnerabilidades para analizar
        if not vulnerabilities:
            self.logger.info("No se encontraron vulnerabilidades para analizar dinámicamente")
            self.logger.info("Esto puede deberse a:")
            self.logger.info("  - Error en la extracción del PDF")
            self.logger.info("  - PDF sin vulnerabilidades reportadas")
            self.logger.info("  - Formato de datos no compatible")
            
            # Agregar información de diagnóstico
            results["analysis_metadata"]["status"] = "NO_VULNERABILITIES_FOUND"
            results["analysis_metadata"]["extractor_data_status"] = "present" if extractor_data else "missing"
            results["analysis_metadata"]["static_data_status"] = "present" if static_data else "missing"
            
            if extractor_data and isinstance(extractor_data, dict):
                results["analysis_metadata"]["extractor_error"] = extractor_data.get("processing_error", "none")
            
            return results
        
        # Procesar cada vulnerabilidad con ReAct
        self.logger.info(f"Iniciando análisis dinámico de {len(vulnerabilities)} vulnerabilidades")
        for i, vuln in enumerate(vulnerabilities, 1):
            self.logger.info(f"Analizando vulnerabilidad {i}/{len(vulnerabilities)}: {vuln.get('title', 'Sin título')}")
            validation_result = self._react_vulnerability_analysis(vuln, target_url, extractor_data, static_data)
            results["vulnerability_validations"].append(validation_result)
        
        results["analysis_metadata"]["status"] = "COMPLETED"
        return results
    
    def _extract_vulnerabilities_from_data(self, extractor_data: Dict[str, Any], 
                                         static_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extrae vulnerabilidades de los datos del extractor y análisis estático"""
        vulnerabilities = []
        
        # Extraer del extractor con manejo de errores mejorado
        if extractor_data:
            if isinstance(extractor_data, dict):
                if 'vulnerabilities' in extractor_data and extractor_data['vulnerabilities']:
                    vulnerabilities.extend(extractor_data['vulnerabilities'])
                elif 'processing_error' in extractor_data:
                    self.logger.warning(f"Error en datos del extractor: {extractor_data['processing_error']}")
                    self.logger.info("Continuando con análisis dinámico sin vulnerabilidades del extractor")
            else:
                self.logger.warning(f"Datos del extractor no son un diccionario válido: {type(extractor_data)}")
        
        # Extraer del análisis estático
        if static_data and isinstance(static_data, dict):
            if 'vulnerabilities' in static_data and static_data['vulnerabilities']:
                vulnerabilities.extend(static_data['vulnerabilities'])
            elif 'findings' in static_data and static_data['findings']:
                vulnerabilities.extend(static_data['findings'])
        
        self.logger.info(f"Total de vulnerabilidades extraídas para análisis dinámico: {len(vulnerabilities)}")
        return vulnerabilities
    
    def _react_vulnerability_analysis(self, vulnerability: Dict[str, Any], 
                                     target_url: str,
                                     extractor_data: Dict[str, Any],
                                     static_data: Dict[str, Any]) -> Dict[str, Any]:
        """Implementa el ciclo ReAct para una vulnerabilidad específica con múltiples intentos"""
        
        vuln_id = vulnerability.get('id', f"vuln_{int(time.time())}")
        vuln_type = vulnerability.get('type', 'unknown')
        vuln_title = vulnerability.get('title', 'Unknown Vulnerability')
        
        react_log = []
        max_iterations = 9  # Aumentado significativamente para más intentos
        current_iteration = 0
        failed_attempts = 0
        max_failed_attempts = 3  # Aumentado para permitir más intentos fallidos
        
        # Estado inicial
        context = {
            "vulnerability": vulnerability,
            "target_url": target_url,
            "extractor_data": extractor_data,
            "static_data": static_data,
            "evidence_found": False,
            "exploitation_status": "NOT_TESTED",
            "confidence_level": "LOW",
            "attempted_techniques": [],  # Registro de técnicas intentadas
            "partial_evidence": [],      # Evidencia parcial acumulada
            "failed_commands": []        # Comandos que fallaron
        }
        
        self.logger.info(f"Iniciando análisis ReAct para vulnerabilidad: {vuln_title} (máximo {max_iterations} iteraciones)")
        
        while current_iteration < max_iterations:
            current_iteration += 1
            self.logger.debug(f"Iniciando iteración {current_iteration}/{max_iterations} para {vuln_title}")
            
            # REASONING: Analizar situación actual y planificar próxima acción
            reasoning = self._reason_about_vulnerability(context, react_log)
            react_log.append({
                "iteration": current_iteration,
                "type": "reasoning",
                "content": reasoning,
                "timestamp": time.time()
            })
            
            # ACTION: Ejecutar la acción planificada
            action_result = self._execute_planned_action(reasoning, context)
            react_log.append({
                "iteration": current_iteration,
                "type": "action",
                "content": action_result,
                "timestamp": time.time()
            })
            
            # EVALUATION: Evaluar resultados y actualizar contexto
            previous_status = context["exploitation_status"]
            context = self._evaluate_action_results(action_result, context)
            
            # Registrar técnica intentada
            technique = reasoning.get("next_action", "unknown")
            if technique not in context["attempted_techniques"]:
                context["attempted_techniques"].append(technique)
            
            # Manejar comandos fallidos
            if not action_result.get("execution_result", {}).get("success", False):
                failed_command = reasoning.get("command", "")
                if failed_command:
                    context["failed_commands"].append(failed_command)
                failed_attempts += 1
            else:
                failed_attempts = 0  # Reset contador si el comando fue exitoso
            
            # Condiciones de terminación (más permisivas)
            # 1. Evidencia concluyente encontrada
            if context["evidence_found"] and context["exploitation_status"] == "EXPLOITABLE":
                self.logger.info(f"Vulnerabilidad confirmada como explotable en iteración {current_iteration}")
                break
                
            # 2. Evidencia negativa concluyente SOLO con alta confianza Y múltiples intentos
            if (context["exploitation_status"] == "NOT_EXPLOITABLE" and 
                context["confidence_level"] == "HIGH" and 
                current_iteration >= 6):  # Requiere al menos 6 intentos
                self.logger.info(f"Vulnerabilidad confirmada como no explotable después de {current_iteration} intentos")
                break
                
            # 3. Demasiados intentos fallidos consecutivos (más permisivo)
            if failed_attempts >= max_failed_attempts and current_iteration >= 8:
                self.logger.warning(f"Demasiados intentos fallidos consecutivos ({failed_attempts}) después de {current_iteration} iteraciones")
                context["exploitation_status"] = "INCONCLUSIVE"
                context["confidence_level"] = "MEDIUM"  # Cambiado de LOW a MEDIUM
                react_log.append({
                    "iteration": current_iteration,
                    "type": "termination",
                    "content": {
                        "reason": "Demasiados intentos fallidos consecutivos después de exploración extensa",
                        "failed_attempts": failed_attempts,
                        "total_iterations": current_iteration
                    },
                    "timestamp": time.time()
                })
                break
                
            # 4. Sin progreso solo después de muchos más intentos
            if current_iteration >= 10 and context["exploitation_status"] == "NOT_TESTED":
                self.logger.warning(f"Sin progreso después de {current_iteration} intentos")
                context["exploitation_status"] = "INCONCLUSIVE"
                context["confidence_level"] = "MEDIUM"  # Cambiado de LOW a MEDIUM
                react_log.append({
                    "iteration": current_iteration,
                    "type": "termination",
                    "content": {
                        "reason": "Sin progreso después de exploración extensa",
                        "attempted_techniques": context["attempted_techniques"],
                        "total_iterations": current_iteration
                    },
                    "timestamp": time.time()
                })
                break
                
            # Log de progreso cada 3 iteraciones
            if current_iteration % 3 == 0:
                self.logger.info(f"Progreso análisis dinámico - Iteración {current_iteration}/{max_iterations}, Estado: {context['exploitation_status']}, Técnicas intentadas: {len(context['attempted_techniques'])}")
        
        # Si llegamos al máximo de iteraciones sin evidencia concluyente
        if current_iteration >= max_iterations and context["exploitation_status"] in ["NOT_TESTED", "INCONCLUSIVE"]:
            context["exploitation_status"] = "NOT_EXPLOITABLE"
            context["confidence_level"] = "MEDIUM"
            react_log.append({
                "iteration": current_iteration,
                "type": "termination",
                "content": {
                    "reason": "Máximo de iteraciones alcanzado sin evidencia de explotación",
                    "total_attempts": current_iteration,
                    "techniques_tried": len(context["attempted_techniques"])
                },
                "timestamp": time.time()
            })
        
        # Log final del análisis
        self.logger.info(f"Análisis ReAct completado para {vuln_title}: {current_iteration} iteraciones, Estado: {context['exploitation_status']}, Confianza: {context['confidence_level']}, Técnicas: {len(context['attempted_techniques'])}")
        
        # Compilar resultado final simplificado
        return {
            "vulnerability_id": vuln_id,
            "vulnerability_title": vuln_title,
            "vulnerability_type": vuln_type,
            "exploitation_status": context["exploitation_status"],
            "confidence_level": context["confidence_level"],
            "evidence": context.get("final_evidence", {}),
            "react_log": react_log
        }
    
    def _reason_about_vulnerability(self, context: Dict[str, Any], react_log: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Fase de razonamiento: analiza la situación y planifica la próxima acción"""
        
        vulnerability = context["vulnerability"]
        target_url = context["target_url"]
        
        # Construir prompt para el LLM
        prompt = f"""
        Eres un experto en penetration testing analizando una vulnerabilidad específica.
        
        VULNERABILIDAD:
        - Tipo: {vulnerability.get('type', 'unknown')}
        - Título: {vulnerability.get('title', 'Unknown')}
        - CWE: {vulnerability.get('cwe', 'N/A')}
        - Severidad: {vulnerability.get('severity', 'unknown')}
        - URL: {vulnerability.get('affected_url', target_url)}
        - Descripción: {vulnerability.get('description', 'N/A')}
        
        DETALLE DE EXPLOTACIÓN (POC):
        {vulnerability.get('detailed_poc', 'No se proporcionó información detallada de explotación')}
        
        INFORMACIÓN TÉCNICA DETALLADA:
        - Componente afectado: {vulnerability.get('affected_component', 'N/A')}
        - Impacto: {vulnerability.get('impact', 'N/A')}
{self._format_optional_field(vulnerability, 'http_requests', 'Solicitudes HTTP')}{self._format_optional_field(vulnerability, 'http_responses', 'Respuestas HTTP')}{self._format_optional_field(vulnerability, 'payloads', 'Payloads específicos')}{self._format_optional_field(vulnerability, 'vulnerable_code_snippets', 'Código vulnerable')}{self._format_optional_field(vulnerability, 'evidences', 'Evidencias adicionales')}{self._format_optional_field(vulnerability, 'references', 'Referencias')}        
        
        CONTEXTO ACTUAL:
        - URL objetivo: {target_url}
        - Estado de explotación: {context['exploitation_status']}
        - Evidencia encontrada: {context['evidence_found']}
        - Nivel de confianza: {context['confidence_level']}
        - Técnicas ya intentadas: {context.get('attempted_techniques', [])}
        - Comandos que fallaron: {context.get('failed_commands', [])}
        - Evidencia parcial acumulada: {context.get('partial_evidence', [])}
        
        HISTORIAL DE ACCIONES PREVIAS:
        {self._format_react_log_for_reasoning(react_log)}
        
        DATOS DEL EXTRACTOR:
        {json.dumps(context.get('extractor_data', {}), indent=2)[:500]}...
        
        DATOS DEL ANÁLISIS ESTÁTICO:
        {json.dumps(context.get('static_data', {}), indent=2)[:500]}...
        
        INSTRUCCIONES IMPORTANTES:
        - Analiza toda la informacion de la vulnerabilidad para replicar su explotacion
        - Si el POC incluye pasos específicos, síguelos o adáptalos para tu testing dinámico
        - Si la vulnerabilidadmenciona payloads específicos, úsalos en tus comandos curl
        - Si obtuviste un error de autorizacion, permisos o autenticacion, revisa si el agente extractor incluyo credenciales
        - Si la vulnerabilidaddescribe parámetros específicos, inclúyelos en tus pruebas
        - NO repitas técnicas que ya intentaste sin éxito
        - NO uses comandos que ya fallaron anteriormente
        - Si una técnica falló, intenta una variación basada en el la vulnerabilidad
        - Considera la evidencia parcial acumulada para construir sobre intentos previos
        - Si has agotado las técnicas del la vulnerabilidad, prueba variaciones creativas
        
        Basándote en toda esta información, especialmente el DETALLE DE EXPLOTACIÓN, razona sobre:
        1. ¿Qué pasos específicos la vulnerabilidadpuedes implementar con comandos Linux?
        2. ¿Qué payloads o parámetros la vulnerabilidadpuedes usar en tus pruebas, hay payloads especificos?
        3. ¿Cómo puedes adaptar los pasos la vulnerabilidadque fallaron anteriormente?
        4. ¿Cuál debería ser tu próxima acción basada en la vulnerabilidad?
        5. ¿Qué comando Linux específico ejecutarías siguiendo la vulnerabilidad?
        6. ¿Qué evidencia específica la vulnerabilidadbuscas en la respuesta?
        
        Responde en formato JSON con esta estructura:
        {{
            "analysis": "Tu análisis de la situación actual y lecciones aprendidas",
            "poc_analysis": "Cómo estás interpretando y usando el DETALLE DE EXPLOTACIÓN (POC)",
            "poc_implementation": "Qué pasos específicos la vulnerabilidad vas a implementar en tu comando",
            "lessons_learned": "Qué has aprendido de los intentos previos",
            "next_action": "Descripción de la próxima acción basada en la vulnerabilidad",
            "command": "Comando Linux específico que implementa pasos del POC",
            "expected_evidence": "Qué evidencia específica la vulnerabilidad esperas encontrar",
            "reasoning": "Por qué esta implementación la vulnerabilidad es apropiada ahora",
            "strategy_adaptation": "Cómo has adaptado la vulnerabilidad basándote en resultados previos"
        }}
        """
        
        try:
            response = self.llm.invoke(prompt)
            # Intentar extraer JSON de la respuesta
            content = response.content.strip()
            
            # Si la respuesta contiene markdown, extraer el JSON
            if "```json" in content:
                start = content.find("```json") + 7
                end = content.find("```", start)
                if end != -1:
                    content = content[start:end].strip()
            elif "```" in content:
                start = content.find("```") + 3
                end = content.find("```", start)
                if end != -1:
                    content = content[start:end].strip()
            
            reasoning_result = json.loads(content)
            
            # Validar que tenga los campos requeridos
            required_fields = ["analysis", "poc_analysis", "poc_implementation", "next_action", "command", "expected_evidence", "reasoning"]
            for field in required_fields:
                if field not in reasoning_result:
                    reasoning_result[field] = f"Campo {field} no especificado"
                    
            return reasoning_result
            
        except Exception as e:
            # Fallback si falla el parsing JSON
            vuln_type = context["vulnerability"].get("type", "unknown").lower()
            
            # Comandos específicos por tipo de vulnerabilidad usando URL específica si está disponible
            vuln_url = vulnerability.get('affected_url', target_url)
            fallback_commands = {
                "idor": f"curl -s '{vuln_url}' -H 'User-Agent: ReAct-Agent'",
                "xss": f"curl -s '{vuln_url}?test=<script>alert(1)</script>' -H 'User-Agent: ReAct-Agent'",
                "sqli": f"curl -s '{vuln_url}?id=1' -H 'User-Agent: ReAct-Agent'",
                "lfi": f"curl -s '{vuln_url}?file=../../../etc/passwd' -H 'User-Agent: ReAct-Agent'"
            }
            
            fallback_command = fallback_commands.get(vuln_type, f"curl -I {vulnerability.get('affected_url', target_url)}")
            
            return {
                "analysis": f"Error en razonamiento LLM: {str(e)}. Usando estrategia de fallback.",
                "poc_analysis": f"POC disponible: {vulnerability.get('detailed_poc', 'No disponible')[:100]}...",
                "poc_implementation": "Implementación básica de fallback sin usar POC específico",
                "lessons_learned": "El LLM no pudo generar una respuesta válida",
                "next_action": f"Realizar prueba básica para {vuln_type}",
                "command": fallback_command,
                "expected_evidence": f"Respuesta del servidor para detectar {vuln_type}",
                "reasoning": "Acción de fallback basada en el tipo de vulnerabilidad",
                "strategy_adaptation": "Usando comando predefinido debido a error del LLM"
            }
    
    def _execute_planned_action(self, reasoning: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Ejecuta la acción planificada en la fase de razonamiento"""
        
        command = reasoning.get("command", "")
        if not command:
            return {
                "success": False,
                "error": "No se especificó comando a ejecutar",
                "reasoning": reasoning
            }
        
        # Ejecutar comando usando la herramienta Linux
        execution_result = self.linux_tool._run(command)
        
        return {
            "reasoning": reasoning,
            "execution_result": execution_result,
            "command_executed": command,
            "timestamp": time.time()
        }
    
    def _evaluate_action_results(self, action_result: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Evalúa los resultados de la acción y actualiza el contexto con evidencia parcial"""
        
        execution_result = action_result.get("execution_result", {})
        reasoning = action_result.get("reasoning", {})
        
        # Analizar si encontramos evidencia
        evidence_analysis = self._analyze_command_output_for_evidence(
            execution_result, 
            reasoning.get("expected_evidence", ""),
            context["vulnerability"]
        )
        
        # Actualizar contexto basado en los resultados
        updated_context = context.copy()
        
        # Manejar evidencia concluyente positiva
        if evidence_analysis["evidence_found"]:
            updated_context["evidence_found"] = True
            updated_context["exploitation_status"] = evidence_analysis["exploitation_status"]
            updated_context["confidence_level"] = evidence_analysis["confidence_level"]
            updated_context["final_evidence"] = evidence_analysis["evidence_details"]
            
        # Manejar evidencia concluyente negativa (más restrictivo)
        elif (evidence_analysis["conclusive_negative"] and 
              evidence_analysis["confidence_level"] == "HIGH" and
              len(updated_context["attempted_techniques"]) >= 4):  # Requiere al menos 4 técnicas intentadas
            self.logger.info(f"Marcando vulnerabilidad como no explotable después de {len(updated_context['attempted_techniques'])} técnicas intentadas")
            updated_context["exploitation_status"] = "NOT_EXPLOITABLE"
            updated_context["confidence_level"] = "HIGH"
            updated_context["evidence_found"] = True  # Evidencia negativa concluyente
            
        # Manejar evidencia parcial o información útil
        elif evidence_analysis.get("partial_evidence"):
            # Acumular evidencia parcial
            partial_info = {
                "command": action_result.get("command_executed", ""),
                "output_snippet": execution_result.get("stdout", "")[:200],
                "analysis": evidence_analysis.get("analysis", ""),
                "timestamp": action_result.get("timestamp", time.time())
            }
            updated_context["partial_evidence"].append(partial_info)
            
            # Actualizar nivel de confianza basado en evidencia acumulada
            if len(updated_context["partial_evidence"]) >= 3:
                if updated_context["confidence_level"] == "LOW":
                    updated_context["confidence_level"] = "MEDIUM"
                    
        # Evaluar progreso general
        if execution_result.get("success", False):
            # Comando exitoso pero sin evidencia concluyente
            if updated_context["exploitation_status"] == "NOT_TESTED":
                updated_context["exploitation_status"] = "TESTING_IN_PROGRESS"
        else:
            # Comando falló - puede indicar protecciones o configuración incorrecta
            error_info = {
                "command": action_result.get("command_executed", ""),
                "error": execution_result.get("stderr", ""),
                "return_code": execution_result.get("return_code", -1),
                "timestamp": action_result.get("timestamp", time.time())
            }
            updated_context["failed_commands"].append(error_info)
        
        return updated_context
    
    def _analyze_command_output_for_evidence(self, execution_result: Dict[str, Any], 
                                           expected_evidence: str,
                                           vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Analiza la salida del comando para buscar evidencia de vulnerabilidad usando LLM"""
        
        if not execution_result.get("success", False):
            return {
                "evidence_found": False,
                "conclusive_negative": False,
                "partial_evidence": False,
                "analysis": "Comando falló en la ejecución"
            }
        
        stdout = execution_result.get("stdout", "")
        stderr = execution_result.get("stderr", "")
        return_code = execution_result.get("return_code", 0)
        
        # Usar LLM para analizar la salida con criterios específicos para respuestas HTTP
        analysis_prompt = f"""
        Eres un experto en análisis de vulnerabilidades de seguridad. Analiza la siguiente salida de comando para determinar si hay evidencia de vulnerabilidad.
        
        VULNERABILIDAD BUSCADA:
        - Tipo: {vulnerability.get('type', 'unknown')}
        - CWE: {vulnerability.get('cwe', 'N/A')}
        - Descripción: {vulnerability.get('description', 'N/A')}
        
        DETALLE DE EXPLOTACIÓN (POC):
        {vulnerability.get('detailed_poc', 'No se proporcionó información detallada de explotación')}
        
        EVIDENCIA ESPERADA:
        {expected_evidence}
        
        SALIDA DEL COMANDO:
        STDOUT:
        {stdout}
        
        STDERR:
        {stderr}
        
        CÓDIGO DE RETORNO: {return_code}
        
        Usa específicamente el DETALLE DE EXPLOTACIÓN (POC) para entender qué evidencia buscar. Compara la salida del comando con lo que se describe en el POC para determinar si la vulnerabilidad fue explotada exitosamente.
        
        IMPORTANTE: 
        - Analiza códigos de estado HTTP, headers, contenido de respuesta y tiempos
        - 
        - Considera el contexto completo, no solo códigos de estado
        - PREFIERE "partial_evidence" o "INCONCLUSIVE" sobre "conclusive_negative" a menos que haya evidencia CLARA de que la vulnerabilidad no existe
        - Solo marca como "conclusive_negative" si hay protecciones evidentes (WAF, filtros, etc.) o respuestas que claramente indican que la vulnerabilidad está parcheada
        - Errores de conexión, timeouts o comandos fallidos NO son evidencia concluyente negativa
        
        Responde ÚNICAMENTE en formato JSON válido:
        {{
            "evidence_found": boolean,
            "exploitation_status": "EXPLOITABLE|NOT_EXPLOITABLE|PARTIAL|INCONCLUSIVE",
            "confidence_level": "HIGH|MEDIUM|LOW",
            "conclusive_negative": boolean,
            "partial_evidence": boolean,
            "evidence_details": {{
                "indicators": ["lista de indicadores específicos encontrados"],
                "explanation": "explicación detallada del análisis",
                "next_steps": "sugerencias para próximos intentos si aplica"
            }},
            "analysis": "análisis técnico detallado de la salida"
        }}
        """
        
        try:
            response = self.llm.invoke(analysis_prompt)
            
            # Extraer JSON del bloque de código markdown si está presente
            content = response.content.strip()
            if content.startswith('```json'):
                # Extraer contenido entre ```json y ```
                start_marker = '```json'
                end_marker = '```'
                start_idx = content.find(start_marker) + len(start_marker)
                end_idx = content.find(end_marker, start_idx)
                if end_idx != -1:
                    content = content[start_idx:end_idx].strip()
            elif content.startswith('```'):
                # Extraer contenido entre ``` y ```
                lines = content.split('\n')
                if len(lines) > 2 and lines[0].startswith('```') and lines[-1].strip() == '```':
                    content = '\n'.join(lines[1:-1]).strip()
            
            analysis_result = json.loads(content)
            
            # Validar que el resultado tenga los campos requeridos
            required_fields = ['evidence_found', 'exploitation_status', 'confidence_level', 
                             'conclusive_negative', 'partial_evidence', 'evidence_details', 'analysis']
            
            for field in required_fields:
                if field not in analysis_result:
                    analysis_result[field] = False if field in ['evidence_found', 'conclusive_negative', 'partial_evidence'] else "INCONCLUSIVE" if field == 'exploitation_status' else "LOW" if field == 'confidence_level' else {} if field == 'evidence_details' else "Campo no especificado"
            
            return analysis_result
            
        except Exception as e:
            # Si falla el LLM, retornar resultado inconcluyente
            return {
                "evidence_found": False,
                "exploitation_status": "INCONCLUSIVE",
                "confidence_level": "LOW",
                "conclusive_negative": False,
                "partial_evidence": False,
                "evidence_details": {
                    "indicators": [],
                    "explanation": f"Error en análisis LLM: {str(e)}",
                    "next_steps": "Revisar manualmente la salida del comando"
                },
                "analysis": f"Error al procesar respuesta del LLM: {str(e)}"
            }
    

    
    def _format_react_log_for_reasoning(self, react_log: List[Dict[str, Any]]) -> str:
        """Formatea el log de ReAct para incluir en el prompt de razonamiento"""
        if not react_log:
            return "No hay acciones previas."
        
        formatted_log = []
        for entry in react_log[-3:]:  # Solo las últimas 3 entradas
            if entry["type"] == "reasoning":
                formatted_log.append(f"RAZONAMIENTO {entry['iteration']}: {entry['content'].get('analysis', 'N/A')}")
            elif entry["type"] == "action":
                cmd = entry['content'].get('command_executed', 'N/A')
                success = entry['content'].get('execution_result', {}).get('success', False)
                formatted_log.append(f"ACCIÓN {entry['iteration']}: {cmd} (Éxito: {success})")
        
        return "\n".join(formatted_log)
    
    def _format_array_field(self, field_value) -> str:
        """Formatea campos que pueden ser arrays o strings para mostrar en prompts"""
        if not field_value:
            return "No disponible"
        
        if isinstance(field_value, list):
            if not field_value:
                return "No disponible"
            elif len(field_value) == 1:
                return str(field_value[0])
            else:
                formatted_items = []
                for i, item in enumerate(field_value[:3], 1):  # Máximo 3 items
                    formatted_items.append(f"  {i}. {str(item)[:200]}{'...' if len(str(item)) > 200 else ''}")
                if len(field_value) > 3:
                    formatted_items.append(f"  ... y {len(field_value) - 3} más")
                return "\n" + "\n".join(formatted_items)
        else:
            return str(field_value)
    
    def _format_optional_field(self, vulnerability: Dict[str, Any], field_name: str, label: str) -> str:
        """Formatea campos opcionales, omitiendo la línea si no están presentes"""
        field_value = vulnerability.get(field_name)
        if not field_value:
            return ""
        
        formatted_value = self._format_array_field(field_value)
        if formatted_value == "No disponible":
            return ""
        
        return f"        - {label}: {formatted_value}\n"