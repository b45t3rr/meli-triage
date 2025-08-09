#!/usr/bin/env python3
"""
Herramienta para extraer texto de archivos PDF
Utilizada por el agente extractor para procesar reportes de vulnerabilidades
"""

import os
import re
from typing import Dict, Any, List
from crewai.tools import BaseTool
from pydantic import BaseModel, Field
import PyPDF2
import logging
from unidecode import unidecode

class PDFExtractorInput(BaseModel):
    """Input schema para la herramienta de extracción de PDF"""
    pdf_path: str = Field(description="Ruta al archivo PDF a procesar")
    extract_metadata: bool = Field(default=True, description="Si extraer metadatos del PDF")
    clean_text: bool = Field(default=True, description="Si limpiar y normalizar el texto extraído")

class PDFExtractorTool(BaseTool):
    """Herramienta para extraer texto y metadatos de archivos PDF"""
    
    name: str = "PDF Extractor"
    description: str = """
    Extrae texto completo y metadatos de archivos PDF de reportes de vulnerabilidades.
    Puede procesar reportes de seguridad, análisis de penetration testing, y documentos técnicos.
    Retorna texto estructurado y metadatos para análisis posterior.
    """
    args_schema: type[BaseModel] = PDFExtractorInput
    
    def _run(self, pdf_path: str, extract_metadata: bool = True, clean_text: bool = True) -> str:
        """Ejecuta la extracción de texto del PDF"""
        logger = logging.getLogger(__name__)
        try:
            if not os.path.exists(pdf_path):
                return f"Error: El archivo {pdf_path} no existe"
            
            if not pdf_path.lower().endswith('.pdf'):
                return f"Error: {pdf_path} no es un archivo PDF válido"
            
            extracted_data = self._extract_pdf_content(pdf_path, extract_metadata, clean_text)
            return self._format_extraction_result(extracted_data)
            
        except Exception as e:
            logger.error(f"Error extrayendo PDF {pdf_path}: {str(e)}")
            return f"Error procesando PDF: {str(e)}"
    
    def _extract_pdf_content(self, pdf_path: str, extract_metadata: bool, clean_text: bool) -> Dict[str, Any]:
        """Extrae contenido del PDF usando PyPDF2"""
        result = {
            "text_content": "",
            "metadata": {},
            "page_count": 0,
            "extraction_stats": {}
        }
        
        with open(pdf_path, 'rb') as file:
            pdf_reader = PyPDF2.PdfReader(file)
            
            if extract_metadata and pdf_reader.metadata:
                result["metadata"] = {
                    "title": pdf_reader.metadata.get('/Title', ''),
                    "author": pdf_reader.metadata.get('/Author', ''),
                    "subject": pdf_reader.metadata.get('/Subject', ''),
                    "creator": pdf_reader.metadata.get('/Creator', ''),
                    "producer": pdf_reader.metadata.get('/Producer', ''),
                    "creation_date": str(pdf_reader.metadata.get('/CreationDate', '')),
                    "modification_date": str(pdf_reader.metadata.get('/ModDate', ''))
                }
            
            result["page_count"] = len(pdf_reader.pages)
            all_text = []
            
            for page_num, page in enumerate(pdf_reader.pages):
                try:
                    page_text = page.extract_text()
                    if page_text.strip():
                        all_text.append(f"\n--- PÁGINA {page_num + 1} ---\n{page_text}")
                except Exception as e:
                    logger.warning(f"Error extrayendo página {page_num + 1}: {str(e)}")
                    continue
            
            raw_text = "\n".join(all_text)
            
            if clean_text:
                result["text_content"] = self._clean_extracted_text(raw_text)
            else:
                result["text_content"] = raw_text
            
            result["extraction_stats"] = {
                "total_characters": len(result["text_content"]),
                "total_words": len(result["text_content"].split()),
                "pages_processed": len(all_text),
                "pages_with_content": len([t for t in all_text if t.strip()])
            }
        
        return result
    
    def _clean_extracted_text(self, text: str) -> str:
        """Limpia y normaliza el texto extraído"""
        # Eliminar caracteres de control
        text = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', text)
        # Normalizar espacios
        text = re.sub(r'\s+', ' ', text)
        # Normalizar saltos de línea
        text = re.sub(r'\n\s*\n', '\n\n', text)
        
        # Normalizar caracteres especiales usando unidecode
        text = unidecode(text)
        
        return text.strip()
    
    def _format_extraction_result(self, data: Dict[str, Any]) -> str:
        """Formatea el resultado de la extracción para el agente"""
        result_parts = []
        
        # Agregar metadatos si están disponibles
        if data["metadata"]:
            result_parts.append("=== METADATOS DEL DOCUMENTO ===")
            for key, value in data["metadata"].items():
                if value:
                    result_parts.append(f"{key.upper()}: {value}")
            result_parts.append("")
        
        # Agregar estadísticas
        stats = data["extraction_stats"]
        result_parts.append("=== ESTADÍSTICAS DE EXTRACCIÓN ===")
        result_parts.append(f"Páginas totales: {data['page_count']}")
        result_parts.append(f"Páginas procesadas: {stats['pages_processed']}")
        result_parts.append(f"Páginas con contenido: {stats['pages_with_content']}")
        result_parts.append(f"Total de caracteres: {stats['total_characters']}")
        result_parts.append(f"Total de palabras: {stats['total_words']}")
        result_parts.append("")
        
        # Agregar contenido del texto
        result_parts.append("=== CONTENIDO EXTRAÍDO ===")
        result_parts.append(data["text_content"])
        
        return "\n".join(result_parts)
            