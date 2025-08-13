#!/usr/bin/env python3
"""
Sistema de Validación de Vulnerabilidades con CrewAI
Arquitectura de 4 agentes para validar vulnerabilidades mediante análisis estático y dinámico
"""

import os
import sys
import json
import re
import logging
import argparse
from datetime import datetime
from typing import Dict, Any, Optional, List
from dotenv import load_dotenv

# Cargar variables de entorno desde .env
load_dotenv()

# Imports de CrewAI
from crewai import Crew, Process
from langchain_openai import ChatOpenAI

# Imports de agentes
from agents.extractor_agent import ExtractorAgent
from agents.static_agent import StaticAgent
from agents.dynamic_agent import DynamicAgent
from agents.triage_agent import TriageAgent

# Imports de herramientas
from tools.pdf_tool import PDFExtractorTool
from tools.semgrep_tool import SemgrepTool

# Removed CurlTool and NmapTool - DynamicAgent now uses GenericLinuxCommandTool internally

# Imports de tareas
from tasks.extraction_task import ExtractionTask
from tasks.static_analysis_task import StaticAnalysisTask
from tasks.dynamic_analysis_task import DynamicAnalysisTask
from tasks.triage_task import TriageTask

# Import de base de datos
from database.mongodb_client import MongoDBClient

# Import de configuración LLM
from config.llm_config import create_llm_instance, get_model_info, list_available_models

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('vulnerability_validation.log'),
        logging.StreamHandler()
    ]
)

class VulnerabilityValidationCrew:
    """Sistema principal de validación de vulnerabilidades"""
    
    def __init__(self, openai_api_key: str, use_mongodb: bool = True, model: str = "gpt-4o-mini"):
        self.logger = logging.getLogger(__name__)
        self.use_mongodb = use_mongodb
        
        try:
            self.llm = create_llm_instance(model, temperature=0.1)
            self.model_info = get_model_info(model)
            self.logger.info(f"Usando modelo: {self.model_info['provider']}:{self.model_info['model']}")
        except Exception as e:
            self.logger.warning(f"Error configurando modelo '{model}': {e}")
            self.logger.info("Usando modelo por defecto OpenAI...")
            self.llm = ChatOpenAI(
                model="gpt-4o-mini",
                api_key=openai_api_key,
                temperature=0.1
            )
            self.model_info = {"provider": "openai", "model": "gpt-4o-mini"}
        
        # Inicializar cliente MongoDB
        self.mongodb_client = None
        if self.use_mongodb:
            self.mongodb_client = MongoDBClient()
            if self.mongodb_client.connect():
                self.logger.info("MongoDB conectado exitosamente")
            else:
                self.logger.warning("No se pudo conectar a MongoDB, continuando sin base de datos")
                self.use_mongodb = False
        
        # Inicializar herramientas
        self.pdf_tool = PDFExtractorTool()
        self.semgrep_tool = SemgrepTool()
        
        # Inicializar agentes con el modelo LLM configurado
        self.extractor_agent = ExtractorAgent(self.pdf_tool, llm=self.llm)
        self.static_agent = StaticAgent(self.semgrep_tool, llm=self.llm)
        self.dynamic_agent = DynamicAgent(llm=self.llm)
        self.triage_agent = TriageAgent(llm=self.llm)
    
    def __del__(self):
        """Destructor para cerrar conexión MongoDB"""
        if self.mongodb_client:
            self.mongodb_client.disconnect()
    
    def validate_vulnerabilities(self, pdf_path: str, source_code_path: str, 
                               target_url: str, output_dir: str = "./results", save_output: bool = False) -> Dict[str, Any]:
        """Ejecuta el proceso completo de validación de vulnerabilidades"""
        
        try:
            self.logger.info("Iniciando proceso de validación de vulnerabilidades")
            
            # Validar archivos de entrada
            if not os.path.exists(pdf_path):
                raise FileNotFoundError(f"Archivo PDF no encontrado: {pdf_path}")
            
            if not os.path.exists(source_code_path):
                raise FileNotFoundError(f"Directorio de código fuente no encontrado: {source_code_path}")
            
            # Crear directorio de resultados
            os.makedirs(output_dir, exist_ok=True)
            
            # Tarea 1: Extracción de vulnerabilidades del PDF
            self.logger.info("Ejecutando extracción de vulnerabilidades...")
            extraction_task = ExtractionTask.create_task(self.extractor_agent.agent, pdf_path)
            
            # Ejecutar solo la extracción primero para obtener los resultados
            extraction_crew = Crew(
                agents=[self.extractor_agent.agent],
                tasks=[extraction_task],
                process=Process.sequential,
                verbose=True
            )
            
            extraction_result = extraction_crew.kickoff()
            self.logger.info("Extracción completada")
            
            # No guardar resultado de extracción en análisis completo - solo se guardará el triage final
            
            # Tarea 2: Análisis estático
            self.logger.info("Ejecutando análisis estático...")
            static_task = StaticAnalysisTask.create_task(
                self.static_agent.agent, 
                str(extraction_result), 
                source_code_path
            )
            
            static_crew = Crew(
                agents=[self.static_agent.agent],
                tasks=[static_task],
                process=Process.sequential,
                verbose=True
            )
            
            static_result = static_crew.kickoff()
            self.logger.info("Análisis estático completado")
            
            # No guardar resultado de análisis estático en análisis completo - solo se guardará el triage final
            
            # Tarea 3: Análisis dinámico
            self.logger.info("Ejecutando análisis dinámico...")
            dynamic_task = DynamicAnalysisTask.create_task(
                self.dynamic_agent.agent,
                str(extraction_result),
                str(static_result),
                target_url
            )
            
            dynamic_crew = Crew(
                agents=[self.dynamic_agent.agent],
                tasks=[dynamic_task],
                process=Process.sequential,
                verbose=True
            )
            
            dynamic_result = dynamic_crew.kickoff()
            self.logger.info("Análisis dinámico completado")
            
            # No guardar resultado de análisis dinámico en análisis completo - solo se guardará el triage final
            
            # Tarea 4: Triage y consolidación
            self.logger.info("Ejecutando triage y consolidación...")
            triage_task = TriageTask.create_task(
                self.triage_agent.agent,
                str(extraction_result),
                str(static_result),
                str(dynamic_result),
                "full"
            )
            
            triage_crew = Crew(
                agents=[self.triage_agent.agent],
                tasks=[triage_task],
                process=Process.sequential,
                verbose=True
            )
            
            final_result = triage_crew.kickoff()
            self.logger.info("Triage completado")
            
            # Procesar y guardar resultado de triage en MongoDB
            if self.use_mongodb and self.mongodb_client:
                try:
                    processed_triage = self._process_triage_result(
                        str(final_result), 
                        str(extraction_result), 
                        str(static_result), 
                        str(dynamic_result),
                        pdf_path,
                        source_code_path,
                        target_url
                    )
                    self.mongodb_client.save_triage_result(
                        processed_triage, 
                        {"timestamp": datetime.now().isoformat()}
                    )
                except Exception as e:
                    self.logger.warning(f"Error guardando triage en MongoDB: {e}")
            
            # Consolidar todos los resultados
            consolidated_results = {
                "extraction_results": str(extraction_result),
                "static_analysis_results": str(static_result),
                "dynamic_analysis_results": str(dynamic_result),
                "final_triage_report": str(final_result),
                "metadata": {
                    "pdf_path": pdf_path,
                    "source_code_path": source_code_path,
                    "target_url": target_url,
                    "analysis_date": datetime.now().isoformat(),
                    "system_version": "1.0.0"
                }
            }
            
            # Guardar resultados
            self._save_results(consolidated_results, output_dir, save_output)
            
            self.logger.info("Proceso de validación completado exitosamente")
            return {
                "status": "success",
                "result": consolidated_results,
                "output_dir": output_dir
            }
            
        except Exception as e:
            self.logger.error(f"Error en el proceso de validación: {str(e)}")
            return {
                "status": "error",
                "error": str(e)
            }
    
    def _process_extraction_result(self, extraction_result: str, pdf_path: str) -> Dict[str, Any]:
        """Procesa el resultado de extracción para formato MongoDB válido"""
        try:
            import re
            
            # Verificar si el resultado está vacío
            if not extraction_result or extraction_result.strip() == "":
                self.logger.warning("Resultado de extracción vacío")
                return {
                    "pdf_path": pdf_path,
                    "vulnerabilities_reported": 0,
                    "vulnerabilities": [],
                    "raw_result": extraction_result,
                    "processing_error": "Resultado de extracción vacío"
                }
            
            # Limpiar el string JSON removiendo marcadores de markdown
            clean_json = extraction_result.strip()
            
            # Log para depuración
            self.logger.debug(f"Resultado de extracción original (primeros 200 chars): {extraction_result[:200]}...")
            
            # Remover marcadores de markdown más robustamente
            if clean_json.startswith('```json'):
                clean_json = clean_json[7:]  # Remover ```json
            elif clean_json.startswith('```'):
                clean_json = clean_json[3:]  # Remover ``` simple
            
            if clean_json.endswith('```'):
                clean_json = clean_json[:-3]  # Remover ```
            
            clean_json = clean_json.strip()
            
            # Buscar JSON válido si aún hay problemas
            if not clean_json.startswith('{'):
                # Buscar el primer { y último }
                start_idx = clean_json.find('{')
                end_idx = clean_json.rfind('}') + 1
                if start_idx != -1 and end_idx > start_idx:
                    clean_json = clean_json[start_idx:end_idx]
                    self.logger.debug(f"JSON extraído por búsqueda de llaves: {clean_json[:100]}...")
            
            # Verificar si después de limpiar queda algo
            if not clean_json:
                self.logger.warning("Resultado de extracción vacío después de limpiar marcadores markdown")
                return {
                    "pdf_path": pdf_path,
                    "vulnerabilities_reported": 0,
                    "vulnerabilities": [],
                    "raw_result": extraction_result,
                    "processing_error": "Resultado vacío después de limpiar markdown"
                }
            
            # Log del JSON limpio para depuración
            self.logger.debug(f"JSON limpio (primeros 200 chars): {clean_json[:200]}...")
            
            # Limpiar escapes Unicode problemáticos antes de parsear
            clean_json = self._fix_unicode_escapes(clean_json)
            
            # Parsear el JSON del resultado
            result_json = json.loads(clean_json)
            
            # Extraer vulnerabilidades y metadata simplificados
            vulnerabilities = result_json.get('vulnerabilities', [])
            metadata = result_json.get('metadata', {})
            
            # Estructurar datos simplificados para MongoDB
            processed_data = {
                "pdf_path": pdf_path,
                "vulnerabilities_reported": len(vulnerabilities),
                "vulnerabilities": vulnerabilities,  # Solo contiene: id, title, severity, type, affected_url, detailed_poc, evidences, remediation
                "document_metadata": {
                    "report_title": metadata.get('report_title', 'N/A'),
                    "scan_date": metadata.get('scan_date', 'N/A'),
                    "target_info": metadata.get('target_info', 'N/A')
                }
            }
            
            self.logger.info(f"Extracción procesada exitosamente: {len(vulnerabilities)} vulnerabilidades encontradas")
            return processed_data
            
        except json.JSONDecodeError as e:
            self.logger.error(f"Error de JSON en resultado de extracción: {e}")
            self.logger.error(f"Contenido que causó el error (primeros 500 chars): {extraction_result[:500]}...")
            # Fallback: estructura básica
            return {
                "pdf_path": pdf_path,
                "vulnerabilities_reported": 0,
                "vulnerabilities": [],
                "raw_result": extraction_result,
                "processing_error": f"Error JSON: {str(e)}"
            }
        except Exception as e:
            self.logger.error(f"Error inesperado procesando resultado de extracción: {e}")
            self.logger.error(f"Contenido del resultado: {extraction_result[:500]}...")
            # Fallback: estructura básica
            return {
                "pdf_path": pdf_path,
                "vulnerabilities_reported": 0,
                "vulnerabilities": [],
                "raw_result": extraction_result,
                "processing_error": f"Error inesperado: {str(e)}"
            }
    
    def _fix_unicode_escapes(self, json_string: str) -> str:
        """Corrige escapes Unicode problemáticos en el JSON"""
        
        # Función para reemplazar escapes Unicode inválidos
        def fix_escape(match):
            escape_seq = match.group(0)
            try:
                # Intentar decodificar el escape
                decoded = escape_seq.encode().decode('unicode_escape')
                # Re-escapar correctamente para JSON
                return json.dumps(decoded)[1:-1]  # Remover las comillas
            except (UnicodeDecodeError, ValueError):
                # Si falla, escapar los caracteres problemáticos
                return escape_seq.replace('\\', '\\\\')
        
        # Buscar y corregir escapes Unicode problemáticos
        # Patrón para encontrar \uXXXX donde XXXX no son 4 dígitos hexadecimales válidos
        pattern = r'\\u[0-9a-fA-F]{0,3}(?![0-9a-fA-F])'
        json_string = re.sub(pattern, fix_escape, json_string)
        
        # Escapar caracteres problemáticos comunes
        json_string = json_string.replace('\\n', '\\\\n')
        json_string = json_string.replace('\\t', '\\\\t')
        json_string = json_string.replace('\\r', '\\\\r')
        
        # Corregir escapes de barra invertida problemáticos
        json_string = re.sub(r'(?<!\\)\\(?!["\\/bfnrt]|u[0-9a-fA-F]{4})', r'\\\\', json_string)
        
        return json_string
    
    def _process_analysis_result(self, analysis_result: str, analysis_type: str) -> List[Dict[str, Any]]:
        """Procesa resultados de análisis estático o dinámico para formato MongoDB válido"""
        try:
            # Limpiar el string JSON removiendo marcadores de markdown
            clean_json = analysis_result.strip()
            if clean_json.startswith('```json'):
                clean_json = clean_json[7:]  # Remover ```json
            if clean_json.endswith('```'):
                clean_json = clean_json[:-3]  # Remover ```
            clean_json = clean_json.strip()
            
            # Parsear el JSON del resultado
            result_json = json.loads(clean_json)
            
            # Manejar si el resultado es directamente una lista o un objeto
            if isinstance(result_json, list):
                # Si es una lista directamente, devolverla
                return result_json
            elif isinstance(result_json, dict):
                # Si es un objeto, extraer hallazgos/vulnerabilidades según el tipo
                if analysis_type == "static":
                    findings = result_json.get('findings', [])
                    if not findings:
                        findings = result_json.get('vulnerabilities', [])
                    return findings
                elif analysis_type == "dynamic":
                    vulnerabilities = result_json.get('vulnerabilities', [])
                    if not vulnerabilities:
                        vulnerabilities = result_json.get('findings', [])
                    return vulnerabilities
                else:
                    return []
            else:
                return []
                
        except (json.JSONDecodeError, KeyError) as e:
            self.logger.warning(f"Error procesando resultado de {analysis_type}: {e}")
            # Fallback: retornar estructura básica
            return [{
                "raw_result": analysis_result,
                "processing_error": str(e),
                "analysis_type": analysis_type
            }]
    
    def _process_triage_result(self, triage_result: str, extraction_result: str, 
                              static_result: str, dynamic_result: str, 
                              pdf_path: str, source_code_path: str, target_url: str) -> Dict[str, Any]:
        """Procesa el resultado de triage para formato MongoDB válido"""
        try:
            # Limpiar y parsear el resultado de triage
            clean_triage = triage_result.strip()
            if clean_triage.startswith('```json'):
                clean_triage = clean_triage[7:]
            if clean_triage.endswith('```'):
                clean_triage = clean_triage[:-3]
            clean_triage = clean_triage.strip()
            
            triage_json = json.loads(clean_triage)
            
            # Extraer información del resultado de extracción original
            extraction_data = self._process_extraction_result(extraction_result, pdf_path)
            
            # Extraer datos del validation_summary si existe
            validation_summary = triage_json.get('validation_summary', {})
            
            # Estructurar datos simplificados para MongoDB
            processed_data = {
                "analysis_metadata": {
                    "pdf_path": pdf_path,
                    "source_code_path": source_code_path,
                    "target_url": target_url,
                    "analysis_timestamp": datetime.now().isoformat()
                },
                "total_vulnerabilities": validation_summary.get('total_vulnerabilities', triage_json.get('total_vulnerabilities', 0)),
                "confirmed_vulnerabilities": validation_summary.get('confirmed_vulnerabilities', triage_json.get('confirmed_vulnerabilities', 0)),
                "false_positives": validation_summary.get('false_positives', triage_json.get('false_positives', 0)),
                "risk_level": validation_summary.get('overall_risk_level', triage_json.get('risk_level', 'Unknown')),
                "vulnerability_assessments": triage_json.get('vulnerability_assessments', []),  # Solo contiene: vulnerability_id, title, type, original_severity, final_status, final_severity, evidence_summary, remediation
                "remediation_recommendations": triage_json.get('remediation_recommendations', [])
            }
            
            return processed_data
            
        except (json.JSONDecodeError, KeyError) as e:
            self.logger.warning(f"Error procesando resultado de triage: {e}")
            # Fallback: estructura básica
            return {
                "analysis_metadata": {
                    "pdf_path": pdf_path,
                    "source_code_path": source_code_path,
                    "target_url": target_url,
                    "analysis_timestamp": datetime.now().isoformat()
                },
                "raw_triage_result": triage_result,
                "processing_error": str(e)
            }
    
    def _save_results(self, result: Dict[str, Any], output_dir: str, save_output: bool = False) -> None:
        """Guarda los resultados del análisis"""
        if not save_output:
            self.logger.info("Archivos JSON no guardados (usar --save-output para guardarlos)")
            return
            
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Guardar resultado consolidado
        result_file = os.path.join(output_dir, f"validation_result_{timestamp}.json")
        with open(result_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        
        # Guardar cada componente por separado
        components = [
            ("extraction", result.get("extraction_results", "")),
            ("static_analysis", result.get("static_analysis_results", "")),
            ("dynamic_analysis", result.get("dynamic_analysis_results", "")),
            ("final_report", result.get("final_triage_report", ""))
        ]
        
        for component_name, component_data in components:
            component_file = os.path.join(output_dir, f"{component_name}_{timestamp}.json")
            with open(component_file, 'w', encoding='utf-8') as f:
                if isinstance(component_data, str):
                    try:
                        # Intentar parsear como JSON
                        json_data = json.loads(component_data)
                        json.dump(json_data, f, indent=2, ensure_ascii=False)
                    except json.JSONDecodeError:
                        # Si no es JSON válido, guardar como texto plano
                        f.write(component_data)
                else:
                    json.dump(component_data, f, indent=2, ensure_ascii=False)
        
        self.logger.info(f"Resultados guardados en: {result_file}")
    
    def extract_only(self, pdf_path: str, output_dir: str = "./results", save_output: bool = False) -> Dict[str, Any]:
        """Ejecuta solamente la extracción de vulnerabilidades del PDF"""
        
        try:
            self.logger.info("Iniciando extracción de vulnerabilidades del PDF")
            
            # Validar archivo de entrada
            if not os.path.exists(pdf_path):
                raise FileNotFoundError(f"Archivo PDF no encontrado: {pdf_path}")
            
            # Crear directorio de resultados
            os.makedirs(output_dir, exist_ok=True)
            
            # Tarea de extracción
            self.logger.info("Ejecutando extracción de vulnerabilidades...")
            extraction_task = ExtractionTask.create_task(self.extractor_agent.agent, pdf_path)
            
            # Ejecutar solo la extracción
            extraction_crew = Crew(
                agents=[self.extractor_agent.agent],
                tasks=[extraction_task],
                process=Process.sequential,
                verbose=True
            )
            
            extraction_result = extraction_crew.kickoff()
            self.logger.info("Extracción completada")
            
            # Guardar resultado de extracción en MongoDB
            if self.use_mongodb and self.mongodb_client:
                try:
                    processed_extraction = self._process_extraction_result(str(extraction_result), pdf_path)
                    self.mongodb_client.save_extraction_result(
                        pdf_path, 
                        processed_extraction, 
                        {"timestamp": datetime.now().isoformat(), "mode": "extraction_only"}
                    )
                except Exception as e:
                    self.logger.warning(f"Error guardando extracción en MongoDB: {e}")
            
            # Preparar resultado
            result = {
                "status": "success",
                "mode": "extraction_only",
                "timestamp": datetime.now().isoformat(),
                "extraction_results": str(extraction_result),
                "pdf_path": pdf_path,
                "output_directory": output_dir
            }
            
            # Guardar resultados
            self._save_extraction_results(result, output_dir, save_output)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error en la extracción: {str(e)}")
            return {
                "status": "error",
                "mode": "extraction_only",
                "error": str(e)
            }
    
    def _save_extraction_results(self, result: Dict[str, Any], output_dir: str, save_output: bool = False) -> None:
        """Guarda los resultados de la extracción"""
        if not save_output:
            self.logger.info("Archivos JSON no guardados (usar --save-output para guardarlos)")
            return
            
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Guardar resultado de extracción
        result_file = os.path.join(output_dir, f"extraction_only_{timestamp}.json")
        with open(result_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        
        # Guardar solo los datos de extracción
        extraction_file = os.path.join(output_dir, f"vulnerabilities_extracted_{timestamp}.json")
        with open(extraction_file, 'w', encoding='utf-8') as f:
            extraction_data = result.get("extraction_results", "")
            if isinstance(extraction_data, str):
                try:
                    # Intentar parsear como JSON
                    json_data = json.loads(extraction_data)
                    json.dump(json_data, f, indent=2, ensure_ascii=False)
                except json.JSONDecodeError:
                    # Si no es JSON válido, guardar como texto plano
                    f.write(extraction_data)
            else:
                json.dump(extraction_data, f, indent=2, ensure_ascii=False)
        
        self.logger.info(f"Resultados de extracción guardados en: {result_file}")
        self.logger.info(f"Vulnerabilidades extraídas guardadas en: {extraction_file}")
    
    def static_only(self, pdf_path: str, source_code_path: str, output_dir: str = "./results", save_output: bool = False) -> Dict[str, Any]:
        """Ejecuta extracción + análisis estático + triage"""
        
        try:
            self.logger.info("Iniciando análisis estático (extracción + análisis estático + triage)")
            
            # Validar archivos de entrada
            if not os.path.exists(pdf_path):
                raise FileNotFoundError(f"Archivo PDF no encontrado: {pdf_path}")
            
            if not os.path.exists(source_code_path):
                raise FileNotFoundError(f"Directorio de código fuente no encontrado: {source_code_path}")
            
            # Crear directorio de resultados
            os.makedirs(output_dir, exist_ok=True)
            
            # Tarea 1: Extracción de vulnerabilidades del PDF
            self.logger.info("Ejecutando extracción de vulnerabilidades...")
            extraction_task = ExtractionTask.create_task(self.extractor_agent.agent, pdf_path)
            
            extraction_crew = Crew(
                agents=[self.extractor_agent.agent],
                tasks=[extraction_task],
                process=Process.sequential,
                verbose=True
            )
            
            extraction_result = extraction_crew.kickoff()
            self.logger.info("Extracción completada")
            
            # Tarea 2: Análisis estático
            self.logger.info("Ejecutando análisis estático...")
            static_task = StaticAnalysisTask.create_task(
                self.static_agent.agent, 
                str(extraction_result), 
                source_code_path
            )
            
            static_crew = Crew(
                agents=[self.static_agent.agent],
                tasks=[static_task],
                process=Process.sequential,
                verbose=True
            )
            
            static_result = static_crew.kickoff()
            self.logger.info("Análisis estático completado")
            
            # Tarea 3: Triage y consolidación
            self.logger.info("Ejecutando triage y consolidación...")
            triage_task = TriageTask.create_task(
                self.triage_agent.agent,
                str(extraction_result),
                str(static_result),
                "",  # Sin resultados de análisis dinámico
                "static_only"
            )
            
            triage_crew = Crew(
                agents=[self.triage_agent.agent],
                tasks=[triage_task],
                process=Process.sequential,
                verbose=True
            )
            
            final_result = triage_crew.kickoff()
            self.logger.info("Triage completado")
            
            # Guardar resultado de triage en MongoDB
            if self.use_mongodb and self.mongodb_client:
                try:
                    processed_triage = self._process_triage_result(
                        str(final_result),
                        str(extraction_result),
                        str(static_result),
                        "",  # Sin análisis dinámico
                        pdf_path,
                        source_code_path,
                        ""
                    )
                    self.mongodb_client.save_triage_result(
                        processed_triage, 
                        {"timestamp": datetime.now().isoformat()}
                    )
                except Exception as e:
                    self.logger.warning(f"Error guardando triage en MongoDB: {e}")
            
            # Preparar resultado
            result = {
                "status": "success",
                "mode": "static_only",
                "timestamp": datetime.now().isoformat(),
                "extraction_results": str(extraction_result),
                "static_analysis_results": str(static_result),
                "final_triage_report": str(final_result),
                "pdf_path": pdf_path,
                "source_code_path": source_code_path,
                "output_directory": output_dir
            }
            
            # Guardar resultados
            self._save_static_results(result, output_dir, save_output)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error en el análisis estático: {str(e)}")
            return {
                "status": "error",
                "mode": "static_only",
                "error": str(e)
            }
    
    def dynamic_only(self, pdf_path: str, target_url: str, output_dir: str = "./results", save_output: bool = False) -> Dict[str, Any]:
        """Ejecuta extracción + análisis dinámico + triage"""
        
        try:
            self.logger.info("Iniciando análisis dinámico (extracción + análisis dinámico + triage)")
            
            # Validar archivo de entrada
            if not os.path.exists(pdf_path):
                raise FileNotFoundError(f"Archivo PDF no encontrado: {pdf_path}")
            
            # Crear directorio de resultados
            os.makedirs(output_dir, exist_ok=True)
            
            # Tarea 1: Extracción de vulnerabilidades del PDF
            self.logger.info("Ejecutando extracción de vulnerabilidades...")
            extraction_task = ExtractionTask.create_task(self.extractor_agent.agent, pdf_path)
            
            extraction_crew = Crew(
                agents=[self.extractor_agent.agent],
                tasks=[extraction_task],
                process=Process.sequential,
                verbose=True
            )
            
            extraction_result = extraction_crew.kickoff()
            self.logger.info("Extracción completada")
            
            # Tarea 2: Análisis dinámico usando bucle ReAct directamente
            self.logger.info("Ejecutando análisis dinámico con bucle ReAct...")
            
            # Procesar resultado de extracción para el agente dinámico
            processed_extraction = self._process_extraction_result(str(extraction_result), pdf_path)
            
            # Ejecutar análisis dinámico con bucle ReAct
            dynamic_result = self.dynamic_agent.analyze_vulnerabilities(
                processed_extraction,
                {"findings": []},  # Sin análisis estático
                target_url
            )
            
            self.logger.info("Análisis dinámico completado")
            
            # Convertir resultado a string para compatibilidad con triage
            dynamic_result = json.dumps(dynamic_result, indent=2, ensure_ascii=False)
            
            # Tarea 3: Triage y consolidación
            self.logger.info("Ejecutando triage y consolidación...")
            triage_task = TriageTask.create_task(
                self.triage_agent.agent,
                str(extraction_result),
                "",  # Sin resultados de análisis estático
                str(dynamic_result),
                "dynamic_only"
            )
            
            triage_crew = Crew(
                agents=[self.triage_agent.agent],
                tasks=[triage_task],
                process=Process.sequential,
                verbose=True
            )
            
            final_result = triage_crew.kickoff()
            self.logger.info("Triage completado")
            
            # Guardar resultado de triage en MongoDB
            if self.use_mongodb and self.mongodb_client:
                try:
                    processed_triage = self._process_triage_result(
                        str(final_result),
                        str(extraction_result),
                        "",  # Sin análisis estático
                        str(dynamic_result),
                        pdf_path,
                        "",
                        target_url
                    )
                    self.mongodb_client.save_triage_result(
                        processed_triage, 
                        {"timestamp": datetime.now().isoformat()}
                    )
                except Exception as e:
                    self.logger.warning(f"Error guardando triage en MongoDB: {e}")
            
            # Preparar resultado
            result = {
                "status": "success",
                "mode": "dynamic_only",
                "timestamp": datetime.now().isoformat(),
                "extraction_results": str(extraction_result),
                "dynamic_analysis_results": str(dynamic_result),
                "final_triage_report": str(final_result),
                "pdf_path": pdf_path,
                "target_url": target_url,
                "output_directory": output_dir
            }
            
            # Guardar resultados
            self._save_dynamic_results(result, output_dir, save_output)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error en el análisis dinámico: {str(e)}")
            return {
                "status": "error",
                "mode": "dynamic_only",
                "error": str(e)
            }
    
    def _save_static_results(self, result: Dict[str, Any], output_dir: str, save_output: bool = False) -> None:
        """Guarda los resultados del análisis estático"""
        if not save_output:
            self.logger.info("Archivos JSON no guardados (usar --save-output para guardarlos)")
            return
            
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Guardar resultado completo
        result_file = os.path.join(output_dir, f"static_only_{timestamp}.json")
        with open(result_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        
        # Guardar componentes por separado
        components = [
            ("extraction", result.get("extraction_results", "")),
            ("static_analysis", result.get("static_analysis_results", ""))
        ]
        
        for component_name, component_data in components:
            component_file = os.path.join(output_dir, f"{component_name}_{timestamp}.json")
            with open(component_file, 'w', encoding='utf-8') as f:
                if isinstance(component_data, str):
                    try:
                        json_data = json.loads(component_data)
                        json.dump(json_data, f, indent=2, ensure_ascii=False)
                    except json.JSONDecodeError:
                        f.write(component_data)
                else:
                    json.dump(component_data, f, indent=2, ensure_ascii=False)
        
        self.logger.info(f"Resultados de análisis estático guardados en: {result_file}")
    
    def _save_dynamic_results(self, result: Dict[str, Any], output_dir: str, save_output: bool = False) -> None:
        """Guarda los resultados del análisis dinámico"""
        if not save_output:
            self.logger.info("Archivos JSON no guardados (usar --save-output para guardarlos)")
            return
            
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Guardar resultado completo
        result_file = os.path.join(output_dir, f"dynamic_only_{timestamp}.json")
        with open(result_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        
        # Guardar componentes por separado
        components = [
            ("extraction", result.get("extraction_results", "")),
            ("dynamic_analysis", result.get("dynamic_analysis_results", ""))
        ]
        
        for component_name, component_data in components:
            component_file = os.path.join(output_dir, f"{component_name}_{timestamp}.json")
            with open(component_file, 'w', encoding='utf-8') as f:
                if isinstance(component_data, str):
                    try:
                        json_data = json.loads(component_data)
                        json.dump(json_data, f, indent=2, ensure_ascii=False)
                    except json.JSONDecodeError:
                        f.write(component_data)
                else:
                    json.dump(component_data, f, indent=2, ensure_ascii=False)
        
        self.logger.info(f"Resultados de análisis dinámico guardados en: {result_file}")

def parse_arguments():
    """Parsea los argumentos de línea de comandos"""
    parser = argparse.ArgumentParser(
        description="Sistema de Validación de Vulnerabilidades con CrewAI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  # Validación completa
  python main.py --pdf report.pdf --source ./code --url https://example.com
  python main.py -p vuln_report.pdf -s /path/to/source -u http://localhost:8080
  python main.py --pdf report.pdf --source ./code --url https://app.com --output ./my_results
  
  # Solo extracción de vulnerabilidades del PDF
  python main.py --pdf report.pdf --extract-only
  python main.py -p vuln_report.pdf --extract-only --output ./extraction_results
  
  # Solo análisis estático
  python main.py --pdf report.pdf --source ./code --static-only
  python main.py -p vuln_report.pdf -s /path/to/source --static-only --output ./static_results
  
  # Solo análisis dinámico
  python main.py --pdf report.pdf --url https://example.com --dynamic-only
  python main.py -p vuln_report.pdf -u http://localhost:8080 --dynamic-only --output ./dynamic_results
        """
    )
    
    parser.add_argument(
        "-p", "--pdf",
        required=False,
        help="Ruta al archivo PDF del reporte de vulnerabilidades"
    )
    
    parser.add_argument(
        "-s", "--source",
        help="Ruta al directorio del código fuente a analizar"
    )
    
    parser.add_argument(
        "-u", "--url",
        help="URL objetivo para las pruebas dinámicas"
    )
    
    parser.add_argument(
        "-o", "--output",
        default="./results",
        help="Directorio de salida para los resultados (default: ./results)"
    )
    
    parser.add_argument(
        "--api-key",
        help="OpenAI API Key (también se puede usar la variable OPENAI_API_KEY)"
    )
    
    parser.add_argument(
        "--model",
        default="gpt-4o-mini",
        help="Modelo LLM a usar (default: gpt-4o-mini). Usa --list-models para ver opciones"
    )
    
    parser.add_argument(
        "--list-models",
        action="store_true",
        help="Mostrar modelos LLM disponibles y salir"
    )
    
    parser.add_argument(
        "--extract-only",
        action="store_true",
        help="Ejecutar solamente el agente extractor (no requiere --source ni --url)"
    )
    
    parser.add_argument(
        "--static-only",
        action="store_true",
        help="Ejecutar solo análisis estático (requiere --pdf y --source)"
    )
    
    parser.add_argument(
        "--dynamic-only",
        action="store_true",
        help="Ejecutar solo análisis dinámico (requiere --pdf y --url)"
    )
    
    parser.add_argument(
        "--save-output",
        action="store_true",
        help="Guardar los resultados en archivos JSON (por defecto no se guardan)"
    )
    
    return parser.parse_args()

def main():
    """Función principal"""
    # Capturar tiempo de inicio
    start_time = datetime.now()
    
    # Parsear argumentos
    args = parse_arguments()
    
    # Mostrar modelos disponibles si se solicita
    if args.list_models:
        print(list_available_models())
        sys.exit(0)
    
    # Validar que --pdf sea requerido para operaciones normales
    if not args.pdf:
        print("Error: El argumento --pdf es requerido para operaciones de análisis.")
        print("Usa --list-models para ver los modelos disponibles.")
        sys.exit(1)
    
    PDF_PATH = args.pdf
    SOURCE_CODE_PATH = args.source
    TARGET_URL = args.url
    OUTPUT_DIR = args.output
    
    EXTRACT_ONLY = args.extract_only
    ONLY_STATIC = getattr(args, 'static_only', False)
    ONLY_DYNAMIC = getattr(args, 'dynamic_only', False)
    SAVE_OUTPUT = getattr(args, 'save_output', False)
    
    # Validar que solo se use un modo a la vez
    modes = [EXTRACT_ONLY, ONLY_STATIC, ONLY_DYNAMIC]
    active_modes = sum(modes)
    
    if active_modes > 1:
        print("❌ Error: Solo se puede usar uno de estos modos a la vez:")
        print("  --extract-only, --static-only, --dynamic-only")
        sys.exit(1)
    
    # Validar argumentos según el modo
    if ONLY_STATIC:
        if not SOURCE_CODE_PATH:
            print("❌ Error: --source es requerido cuando se usa --static-only")
            sys.exit(1)
    elif ONLY_DYNAMIC:
        if not TARGET_URL:
            print("❌ Error: --url es requerido cuando se usa --dynamic-only")
            sys.exit(1)
    elif not EXTRACT_ONLY and active_modes == 0:  # Modo completo
        if not SOURCE_CODE_PATH:
            print("❌ Error: --source es requerido para validación completa")
            sys.exit(1)
        if not TARGET_URL:
            print("❌ Error: --url es requerido para validación completa")
            sys.exit(1)
    
    # Obtener API key de OpenAI
    openai_api_key = args.api_key or os.getenv("OPENAI_API_KEY")
    if not openai_api_key:
        print("❌ Error: OpenAI API Key no está configurada")
        print("Opciones:")
        print("  1. Usar --api-key: python main.py --api-key tu-key ...")
        print("  2. Variable de entorno: export OPENAI_API_KEY='tu-key'")
        sys.exit(1)
    
    # Verificar archivos de entrada
    if not os.path.exists(PDF_PATH):
        print(f"❌ Error: Archivo PDF no encontrado: {PDF_PATH}")
        print("Verifica que la ruta sea correcta y el archivo exista")
        sys.exit(1)
    
    # Validar archivos según el modo
    if ONLY_STATIC or (not EXTRACT_ONLY and not ONLY_DYNAMIC and active_modes == 0):
        if not os.path.exists(SOURCE_CODE_PATH):
            print(f"❌ Error: Directorio de código fuente no encontrado: {SOURCE_CODE_PATH}")
            print("Verifica que la ruta sea correcta y el directorio exista")
            sys.exit(1)
    
    if ONLY_DYNAMIC or (not EXTRACT_ONLY and not ONLY_STATIC and active_modes == 0):
        # Validar URL
        if not (TARGET_URL.startswith('http://') or TARGET_URL.startswith('https://')):
            print(f"❌ Error: URL inválida: {TARGET_URL}")
            print("La URL debe comenzar con http:// o https://")
            sys.exit(1)
    
    print("🚀 Iniciando sistema de validación de vulnerabilidades...")
    print(f"⏰ Inicio: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"📄 PDF: {PDF_PATH}")
    
    if EXTRACT_ONLY:
        print("🔍 Modo: Solo extracción")
    elif ONLY_STATIC:
        print("🔍 Modo: Análisis estático + triage")
        print(f"💻 Código: {SOURCE_CODE_PATH}")
    elif ONLY_DYNAMIC:
        print("🔍 Modo: Análisis dinámico + triage")
        print(f"🌐 Target: {TARGET_URL}")
    else:
        print("🔍 Modo: Validación completa")
        print(f"💻 Código: {SOURCE_CODE_PATH}")
        print(f"🌐 Target: {TARGET_URL}")
    
    print(f"📁 Resultados: {OUTPUT_DIR}")
    
    # Mostrar información del modelo utilizado
    model_info = get_model_info(args.model)
    if "error" not in model_info:
        provider_name = model_info["provider"].upper()
        model_name = model_info["model"]
        print(f"🧠 Modelo: {provider_name} - {model_name}")
    else:
        print(f"🧠 Modelo: {args.model}")
    
    print("-" * 50)
    
    # Crear y ejecutar el sistema
    try:
        validation_system = VulnerabilityValidationCrew(openai_api_key, model=args.model)
        
        if EXTRACT_ONLY:
            # Ejecutar solo extracción
            result = validation_system.extract_only(
                pdf_path=PDF_PATH,
                output_dir=OUTPUT_DIR,
                save_output=SAVE_OUTPUT
            )
            
            if result["status"] == "success":
                end_time = datetime.now()
                duration = end_time - start_time
                print("\n" + "=" * 50)
                print("✅ Extracción completada exitosamente")
                print(f"📁 Resultados guardados en: {result['output_directory']}")
                print(f"⏱️  Tiempo de ejecución: {duration}")
                print("\n📊 Archivos generados:")
                print("  - Resultado completo de extracción")
                print("  - Vulnerabilidades extraídas en JSON")
                print("=" * 50)
            else:
                end_time = datetime.now()
                duration = end_time - start_time
                print("\n" + "=" * 50)
                print(f"❌ Error en la extracción: {result['error']}")
                print(f"⏱️  Tiempo de ejecución: {duration}")
                print("=" * 50)
                sys.exit(1)
                
        elif ONLY_STATIC:
            # Ejecutar solo análisis estático
            result = validation_system.static_only(
                pdf_path=PDF_PATH,
                source_code_path=SOURCE_CODE_PATH,
                output_dir=OUTPUT_DIR,
                save_output=SAVE_OUTPUT
            )
            
            if result["status"] == "success":
                end_time = datetime.now()
                duration = end_time - start_time
                print("\n" + "=" * 50)
                print("✅ Análisis estático completado exitosamente")
                print(f"📁 Resultados guardados en: {result['output_directory']}")
                print(f"⏱️  Tiempo de ejecución: {duration}")
                print("\n📊 Componentes generados:")
                print("  - Extracción de vulnerabilidades")
                print("  - Análisis estático (Semgrep)")
                print("  - Triage y consolidación")
                print("=" * 50)
            else:
                end_time = datetime.now()
                duration = end_time - start_time
                print("\n" + "=" * 50)
                print(f"❌ Error en el análisis estático: {result['error']}")
                print(f"⏱️  Tiempo de ejecución: {duration}")
                print("=" * 50)
                sys.exit(1)
                
        elif ONLY_DYNAMIC:
            # Ejecutar solo análisis dinámico
            result = validation_system.dynamic_only(
                pdf_path=PDF_PATH,
                target_url=TARGET_URL,
                output_dir=OUTPUT_DIR,
                save_output=SAVE_OUTPUT
            )
            
            if result["status"] == "success":
                end_time = datetime.now()
                duration = end_time - start_time
                print("\n" + "=" * 50)
                print("✅ Análisis dinámico completado exitosamente")
                print(f"📁 Resultados guardados en: {result['output_directory']}")
                print(f"⏱️  Tiempo de ejecución: {duration}")
                print("\n📊 Componentes generados:")
                print("  - Extracción de vulnerabilidades")
                print("  - Análisis dinámico")
                print("  - Triage y consolidación")
                print("=" * 50)
            else:
                end_time = datetime.now()
                duration = end_time - start_time
                print("\n" + "=" * 50)
                print(f"❌ Error en el análisis dinámico: {result['error']}")
                print(f"⏱️  Tiempo de ejecución: {duration}")
                print("=" * 50)
                sys.exit(1)
                
        else:
            # Ejecutar validación completa
            result = validation_system.validate_vulnerabilities(
                pdf_path=PDF_PATH,
                source_code_path=SOURCE_CODE_PATH,
                target_url=TARGET_URL,
                output_dir=OUTPUT_DIR,
                save_output=SAVE_OUTPUT
            )
            
            if result["status"] == "success":
                end_time = datetime.now()
                duration = end_time - start_time
                print("\n" + "=" * 50)
                print("✅ Validación completada exitosamente")
                print(f"📁 Resultados guardados en: {result['output_dir']}")
                print(f"⏱️  Tiempo de ejecución: {duration}")
                print("\n📊 Componentes generados:")
                print("  - Extracción de vulnerabilidades")
                print("  - Análisis estático (Semgrep)")
                print("  - Análisis dinámico")
                print("  - Reporte final de triage")
                print("=" * 50)
            else:
                end_time = datetime.now()
                duration = end_time - start_time
                print("\n" + "=" * 50)
                print(f"❌ Error en la validación: {result['error']}")
                print(f"⏱️  Tiempo de ejecución: {duration}")
                print("=" * 50)
                sys.exit(1)
            
    except KeyboardInterrupt:
        end_time = datetime.now()
        duration = end_time - start_time
        print(f"\n⚠️  Proceso interrumpido por el usuario")
        print(f"⏱️  Tiempo de ejecución: {duration}")
        sys.exit(1)
    except Exception as e:
        end_time = datetime.now()
        duration = end_time - start_time
        print(f"\n❌ Error inesperado: {str(e)}")
        print(f"⏱️  Tiempo de ejecución: {duration}")
        sys.exit(1)

if __name__ == "__main__":
    main()