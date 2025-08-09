#!/usr/bin/env python3
"""
Sistema de Validación de Vulnerabilidades con CrewAI
Arquitectura de 4 agentes para validar vulnerabilidades mediante análisis estático y dinámico
"""

import os
import sys
import json
import logging
import argparse
from datetime import datetime
from typing import Dict, Any, Optional

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
from tools.nuclei_tool import NucleiTool

# Imports de tareas
from tasks.extraction_task import ExtractionTask
from tasks.static_analysis_task import StaticAnalysisTask
from tasks.dynamic_analysis_task import DynamicAnalysisTask
from tasks.triage_task import TriageTask

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
    
    def __init__(self, openai_api_key: str):
        self.logger = logging.getLogger(__name__)
        self.llm = ChatOpenAI(
            model="gpt-5-mini",
            api_key=openai_api_key,
            temperature=0.1
        )
        
        # Inicializar herramientas
        self.pdf_tool = PDFExtractorTool()
        self.semgrep_tool = SemgrepTool()
        self.nuclei_tool = NucleiTool()
        
        # Inicializar agentes
        self.extractor_agent = ExtractorAgent(self.pdf_tool)
        self.static_agent = StaticAgent(self.semgrep_tool)
        self.dynamic_agent = DynamicAgent(self.nuclei_tool)
        self.triage_agent = TriageAgent()
    
    def validate_vulnerabilities(self, pdf_path: str, source_code_path: str, 
                               target_url: str, output_dir: str = "./results") -> Dict[str, Any]:
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
            
            # Tarea 4: Triage y consolidación
            self.logger.info("Ejecutando triage y consolidación...")
            triage_task = TriageTask.create_task(
                self.triage_agent.agent,
                str(extraction_result),
                str(static_result),
                str(dynamic_result)
            )
            
            triage_crew = Crew(
                agents=[self.triage_agent.agent],
                tasks=[triage_task],
                process=Process.sequential,
                verbose=True
            )
            
            final_result = triage_crew.kickoff()
            self.logger.info("Triage completado")
            
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
            self._save_results(consolidated_results, output_dir)
            
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
    
    def _save_results(self, result: Dict[str, Any], output_dir: str) -> None:
        """Guarda los resultados del análisis"""
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
    
    def extract_only(self, pdf_path: str, output_dir: str = "./results") -> Dict[str, Any]:
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
            self._save_extraction_results(result, output_dir)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error en la extracción: {str(e)}")
            return {
                "status": "error",
                "mode": "extraction_only",
                "error": str(e)
            }
    
    def _save_extraction_results(self, result: Dict[str, Any], output_dir: str) -> None:
        """Guarda los resultados de la extracción"""
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
    
    def static_only(self, pdf_path: str, source_code_path: str, output_dir: str = "./results") -> Dict[str, Any]:
        """Ejecuta extracción + análisis estático solamente"""
        
        try:
            self.logger.info("Iniciando análisis estático (extracción + análisis estático)")
            
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
            
            # Preparar resultado
            result = {
                "status": "success",
                "mode": "static_only",
                "timestamp": datetime.now().isoformat(),
                "extraction_results": str(extraction_result),
                "static_analysis_results": str(static_result),
                "pdf_path": pdf_path,
                "source_code_path": source_code_path,
                "output_directory": output_dir
            }
            
            # Guardar resultados
            self._save_static_results(result, output_dir)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error en el análisis estático: {str(e)}")
            return {
                "status": "error",
                "mode": "static_only",
                "error": str(e)
            }
    
    def dynamic_only(self, pdf_path: str, target_url: str, output_dir: str = "./results") -> Dict[str, Any]:
        """Ejecuta extracción + análisis dinámico solamente"""
        
        try:
            self.logger.info("Iniciando análisis dinámico (extracción + análisis dinámico)")
            
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
            
            # Tarea 2: Análisis dinámico (sin resultados de análisis estático)
            self.logger.info("Ejecutando análisis dinámico...")
            dynamic_task = DynamicAnalysisTask.create_task(
                self.dynamic_agent.agent,
                str(extraction_result),
                "",  # Sin resultados de análisis estático
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
            
            # Preparar resultado
            result = {
                "status": "success",
                "mode": "dynamic_only",
                "timestamp": datetime.now().isoformat(),
                "extraction_results": str(extraction_result),
                "dynamic_analysis_results": str(dynamic_result),
                "pdf_path": pdf_path,
                "target_url": target_url,
                "output_directory": output_dir
            }
            
            # Guardar resultados
            self._save_dynamic_results(result, output_dir)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error en el análisis dinámico: {str(e)}")
            return {
                "status": "error",
                "mode": "dynamic_only",
                "error": str(e)
            }
    
    def _save_static_results(self, result: Dict[str, Any], output_dir: str) -> None:
        """Guarda los resultados del análisis estático"""
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
    
    def _save_dynamic_results(self, result: Dict[str, Any], output_dir: str) -> None:
        """Guarda los resultados del análisis dinámico"""
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
  python main.py --pdf report.pdf --source ./code --onlystatic
  python main.py -p vuln_report.pdf -s /path/to/source --onlystatic --output ./static_results
  
  # Solo análisis dinámico
  python main.py --pdf report.pdf --url https://example.com --onlydynamic
  python main.py -p vuln_report.pdf -u http://localhost:8080 --onlydynamic --output ./dynamic_results
        """
    )
    
    parser.add_argument(
        "-p", "--pdf",
        required=True,
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
        "--extract-only",
        action="store_true",
        help="Ejecutar solamente el agente extractor (no requiere --source ni --url)"
    )
    
    parser.add_argument(
        "--onlystatic",
        action="store_true",
        help="Ejecutar solo análisis estático (requiere --pdf y --source)"
    )
    
    parser.add_argument(
        "--onlydynamic",
        action="store_true",
        help="Ejecutar solo análisis dinámico (requiere --pdf y --url)"
    )
    
    return parser.parse_args()

def main():
    """Función principal"""
    # Parsear argumentos
    args = parse_arguments()
    
    PDF_PATH = args.pdf
    SOURCE_CODE_PATH = args.source
    TARGET_URL = args.url
    OUTPUT_DIR = args.output
    
    EXTRACT_ONLY = args.extract_only
    ONLY_STATIC = args.onlystatic
    ONLY_DYNAMIC = args.onlydynamic
    
    # Validar que solo se use un modo a la vez
    modes = [EXTRACT_ONLY, ONLY_STATIC, ONLY_DYNAMIC]
    active_modes = sum(modes)
    
    if active_modes > 1:
        print("❌ Error: Solo se puede usar uno de estos modos a la vez:")
        print("  --extract-only, --onlystatic, --onlydynamic")
        sys.exit(1)
    
    # Validar argumentos según el modo
    if ONLY_STATIC:
        if not SOURCE_CODE_PATH:
            print("❌ Error: --source es requerido cuando se usa --onlystatic")
            sys.exit(1)
    elif ONLY_DYNAMIC:
        if not TARGET_URL:
            print("❌ Error: --url es requerido cuando se usa --onlydynamic")
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
    print(f"📄 PDF: {PDF_PATH}")
    
    if EXTRACT_ONLY:
        print("🔍 Modo: Solo extracción")
    elif ONLY_STATIC:
        print("🔍 Modo: Solo análisis estático")
        print(f"💻 Código: {SOURCE_CODE_PATH}")
    elif ONLY_DYNAMIC:
        print("🔍 Modo: Solo análisis dinámico")
        print(f"🌐 Target: {TARGET_URL}")
    else:
        print("🔍 Modo: Validación completa")
        print(f"💻 Código: {SOURCE_CODE_PATH}")
        print(f"🌐 Target: {TARGET_URL}")
    
    print(f"📁 Resultados: {OUTPUT_DIR}")
    print("-" * 50)
    
    # Crear y ejecutar el sistema
    try:
        validation_system = VulnerabilityValidationCrew(openai_api_key)
        
        if EXTRACT_ONLY:
            # Ejecutar solo extracción
            result = validation_system.extract_only(
                pdf_path=PDF_PATH,
                output_dir=OUTPUT_DIR
            )
            
            if result["status"] == "success":
                print("\n" + "=" * 50)
                print("✅ Extracción completada exitosamente")
                print(f"📁 Resultados guardados en: {result['output_directory']}")
                print("\n📊 Archivos generados:")
                print("  - Resultado completo de extracción")
                print("  - Vulnerabilidades extraídas en JSON")
                print("=" * 50)
            else:
                print("\n" + "=" * 50)
                print(f"❌ Error en la extracción: {result['error']}")
                print("=" * 50)
                sys.exit(1)
                
        elif ONLY_STATIC:
            # Ejecutar solo análisis estático
            result = validation_system.static_only(
                pdf_path=PDF_PATH,
                source_code_path=SOURCE_CODE_PATH,
                output_dir=OUTPUT_DIR
            )
            
            if result["status"] == "success":
                print("\n" + "=" * 50)
                print("✅ Análisis estático completado exitosamente")
                print(f"📁 Resultados guardados en: {result['output_directory']}")
                print("\n📊 Componentes generados:")
                print("  - Extracción de vulnerabilidades")
                print("  - Análisis estático (Semgrep)")
                print("=" * 50)
            else:
                print("\n" + "=" * 50)
                print(f"❌ Error en el análisis estático: {result['error']}")
                print("=" * 50)
                sys.exit(1)
                
        elif ONLY_DYNAMIC:
            # Ejecutar solo análisis dinámico
            result = validation_system.dynamic_only(
                pdf_path=PDF_PATH,
                target_url=TARGET_URL,
                output_dir=OUTPUT_DIR
            )
            
            if result["status"] == "success":
                print("\n" + "=" * 50)
                print("✅ Análisis dinámico completado exitosamente")
                print(f"📁 Resultados guardados en: {result['output_directory']}")
                print("\n📊 Componentes generados:")
                print("  - Extracción de vulnerabilidades")
                print("  - Análisis dinámico (Nuclei)")
                print("=" * 50)
            else:
                print("\n" + "=" * 50)
                print(f"❌ Error en el análisis dinámico: {result['error']}")
                print("=" * 50)
                sys.exit(1)
                
        else:
            # Ejecutar validación completa
            result = validation_system.validate_vulnerabilities(
                pdf_path=PDF_PATH,
                source_code_path=SOURCE_CODE_PATH,
                target_url=TARGET_URL,
                output_dir=OUTPUT_DIR
            )
            
            if result["status"] == "success":
                print("\n" + "=" * 50)
                print("✅ Validación completada exitosamente")
                print(f"📁 Resultados guardados en: {result['output_dir']}")
                print("\n📊 Componentes generados:")
                print("  - Extracción de vulnerabilidades")
                print("  - Análisis estático (Semgrep)")
                print("  - Análisis dinámico (Nuclei)")
                print("  - Reporte final de triage")
                print("=" * 50)
            else:
                print("\n" + "=" * 50)
                print(f"❌ Error en la validación: {result['error']}")
                print("=" * 50)
                sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n⚠️  Proceso interrumpido por el usuario")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error inesperado: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()