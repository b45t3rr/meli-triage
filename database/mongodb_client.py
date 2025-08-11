#!/usr/bin/env python3
"""
Cliente MongoDB para el sistema de validación de vulnerabilidades
"""

import os
import logging
from datetime import datetime
from typing import Dict, Any, Optional, List
from pymongo import MongoClient
from pymongo.database import Database
from pymongo.collection import Collection
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

class MongoDBClient:
    """Cliente para operaciones con MongoDB"""
    
    def __init__(self, 
                 host: str = None,
                 port: int = None,
                 username: str = None,
                 password: str = None,
                 database_name: str = None):
        
        self.logger = logging.getLogger(__name__)
        
        # Usar variables de entorno con valores por defecto
        self.host = host or os.getenv('MONGO_HOST', 'localhost')
        self.port = port or int(os.getenv('MONGO_PORT', '27017'))
        self.username = username or os.getenv('MONGO_USERNAME', 'admin')
        self.password = password or os.getenv('MONGO_PASSWORD', 'password123')
        self.database_name = database_name or os.getenv('MONGO_DATABASE', 'vulnerability_scanner')
        self.auth_source = os.getenv('MONGO_AUTH_SOURCE', 'admin')
        self.connection_timeout = int(os.getenv('MONGO_CONNECTION_TIMEOUT', '5000'))
        
        # URI de conexión
        self.connection_uri = f"mongodb://{self.username}:{self.password}@{self.host}:{self.port}/{self.database_name}?authSource={self.auth_source}"
        
        self.client: Optional[MongoClient] = None
        self.database: Optional[Database] = None
        
    def connect(self) -> bool:
        """Establece conexión con MongoDB"""
        try:
            self.client = MongoClient(
                self.connection_uri,
                serverSelectionTimeoutMS=self.connection_timeout
            )
            
            # Verificar conexión
            self.client.admin.command('ping')
            self.database = self.client[self.database_name]
            
            self.logger.info(f"Conexión exitosa a MongoDB en {self.host}:{self.port}")
            return True
            
        except (ConnectionFailure, ServerSelectionTimeoutError) as e:
            self.logger.error(f"Error conectando a MongoDB: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Error inesperado conectando a MongoDB: {e}")
            return False
    
    def disconnect(self):
        """Cierra la conexión con MongoDB"""
        if self.client:
            self.client.close()
            self.logger.info("Conexión a MongoDB cerrada")
    
    def get_collection(self, collection_name: str) -> Optional[Collection]:
        """Obtiene una colección de la base de datos"""
        if self.database is None:
            self.logger.error("No hay conexión activa a la base de datos")
            return None
        
        return self.database[collection_name]
    
    def save_scan_result(self, scan_type: str, result_data: Dict[str, Any], 
                        metadata: Optional[Dict[str, Any]] = None) -> Optional[str]:
        """Guarda el resultado de un scan en MongoDB"""
        
        if self.database is None:
            self.logger.error("No hay conexión activa a la base de datos")
            return None
        
        try:
            # Preparar documento
            document = {
                "scan_type": scan_type,
                "timestamp": datetime.utcnow(),
                "result_data": result_data,
                "metadata": metadata or {}
            }
            
            # Insertar en la colección correspondiente
            collection = self.get_collection("scan_results")
            result = collection.insert_one(document)
            
            self.logger.info(f"Resultado de {scan_type} guardado con ID: {result.inserted_id}")
            return str(result.inserted_id)
            
        except Exception as e:
            self.logger.error(f"Error guardando resultado de {scan_type}: {e}")
            return None
    
    def get_scan_results(self, scan_type: Optional[str] = None, 
                        limit: int = 100) -> List[Dict[str, Any]]:
        """Obtiene resultados de scans desde MongoDB"""
        
        if self.database is None:
            self.logger.error("No hay conexión activa a la base de datos")
            return []
        
        try:
            collection = self.get_collection("scan_results")
            
            # Filtro por tipo de scan si se especifica
            query = {"scan_type": scan_type} if scan_type else {}
            
            # Obtener resultados ordenados por timestamp descendente
            cursor = collection.find(query).sort("timestamp", -1).limit(limit)
            
            results = list(cursor)
            
            # Convertir ObjectId a string para serialización JSON
            for result in results:
                result["_id"] = str(result["_id"])
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error obteniendo resultados: {e}")
            return []
    
    def save_extraction_result(self, pdf_path: str, processed_data: Dict[str, Any], 
                              metadata: Optional[Dict[str, Any]] = None) -> Optional[str]:
        """Guarda resultado de extracción de PDF con formato mejorado"""
        
        # El processed_data ya viene estructurado desde main.py
        # Solo necesitamos agregarlo como result_data
        return self.save_scan_result("extraction", processed_data, metadata)
    
    def save_static_analysis_result(self, source_code_path: str, findings: List[Dict[str, Any]], 
                                   metadata: Optional[Dict[str, Any]] = None) -> Optional[str]:
        """Guarda resultado de análisis estático"""
        
        result_data = {
            "source_code_path": source_code_path,
            "findings_count": len(findings),
            "findings": findings
        }
        
        return self.save_scan_result("static_analysis", result_data, metadata)
    
    def save_dynamic_analysis_result(self, target_url: str, vulnerabilities: List[Dict[str, Any]], 
                                    metadata: Optional[Dict[str, Any]] = None) -> Optional[str]:
        """Guarda resultado de análisis dinámico"""
        
        result_data = {
            "target_url": target_url,
            "vulnerabilities_found": len(vulnerabilities),
            "vulnerabilities": vulnerabilities
        }
        
        return self.save_scan_result("dynamic_analysis", result_data, metadata)
    
    def save_triage_result(self, consolidated_results: Dict[str, Any], 
                          metadata: Optional[Dict[str, Any]] = None) -> Optional[str]:
        """Guarda resultado de triage y consolidación"""
        
        return self.save_scan_result("triage", consolidated_results, metadata)
    
    def get_vulnerability_summary(self, limit: int = 10) -> Dict[str, Any]:
        """Obtiene un resumen consolidado de vulnerabilidades reportadas y corroboradas"""
        
        if self.database is None:
            self.logger.error("No hay conexión activa a la base de datos")
            return {}
        
        try:
            collection = self.get_collection("scan_results")
            
            # Obtener resultados de extracción más recientes
            extraction_results = list(collection.find(
                {"scan_type": "extraction"}
            ).sort("timestamp", -1).limit(limit))
            
            # Obtener resultados de triage más recientes
            triage_results = list(collection.find(
                {"scan_type": "triage"}
            ).sort("timestamp", -1).limit(limit))
            
            summary = {
                "extraction_summary": {
                    "total_reports": len(extraction_results),
                    "reports": []
                },
                "triage_summary": {
                    "total_analyses": len(triage_results),
                    "analyses": []
                },
                "consolidated_metrics": {
                    "total_vulnerabilities_reported": 0,
                    "total_vulnerabilities_confirmed": 0,
                    "validation_rate": 0.0,
                    "severity_distribution": {
                        "critical": 0,
                        "high": 0,
                        "medium": 0,
                        "low": 0
                    }
                }
            }
            
            # Procesar resultados de extracción
            total_reported = 0
            for result in extraction_results:
                result_data = result.get("result_data", {})
                vulnerabilities_count = result_data.get("vulnerabilities_reported", 0)
                total_reported += vulnerabilities_count
                
                extraction_summary = result_data.get("extraction_summary", {})
                
                summary["extraction_summary"]["reports"].append({
                    "timestamp": result.get("timestamp"),
                    "pdf_path": result_data.get("pdf_path"),
                    "vulnerabilities_reported": vulnerabilities_count,
                    "severity_breakdown": {
                        "critical": extraction_summary.get("critical_count", 0),
                        "high": extraction_summary.get("high_count", 0),
                        "medium": extraction_summary.get("medium_count", 0),
                        "low": extraction_summary.get("low_count", 0)
                    },
                    "categories": extraction_summary.get("categories", []),
                    "cwe_types": extraction_summary.get("cwe_types", [])
                })
            
            # Procesar resultados de triage
            total_confirmed = 0
            for result in triage_results:
                result_data = result.get("result_data", {})
                confirmed_count = result_data.get("vulnerabilities_confirmed", 0)
                total_confirmed += confirmed_count
                
                validation_summary = result_data.get("validation_summary", {})
                
                summary["triage_summary"]["analyses"].append({
                    "timestamp": result.get("timestamp"),
                    "analysis_metadata": result_data.get("analysis_metadata", {}),
                    "vulnerabilities_reported": result_data.get("vulnerabilities_reported", 0),
                    "vulnerabilities_confirmed": confirmed_count,
                    "validation_breakdown": {
                        "confirmed": validation_summary.get("confirmed", 0),
                        "likely": validation_summary.get("likely", 0),
                        "possible": validation_summary.get("possible", 0),
                        "false_positives": validation_summary.get("false_positives", 0)
                    },
                    "validation_rate": validation_summary.get("validation_rate", 0.0)
                })
            
            # Calcular métricas consolidadas
            summary["consolidated_metrics"]["total_vulnerabilities_reported"] = total_reported
            summary["consolidated_metrics"]["total_vulnerabilities_confirmed"] = total_confirmed
            summary["consolidated_metrics"]["validation_rate"] = (
                (total_confirmed / total_reported * 100) if total_reported > 0 else 0.0
            )
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Error obteniendo resumen de vulnerabilidades: {e}")
            return {}
    
    def get_detailed_vulnerability_analysis(self, analysis_id: str = None) -> Dict[str, Any]:
        """Obtiene análisis detallado de vulnerabilidades con correlación entre reportadas y corroboradas"""
        
        if self.database is None:
            self.logger.error("No hay conexión activa a la base de datos")
            return {}
        
        try:
            collection = self.get_collection("scan_results")
            
            # Si se especifica un ID, buscar ese análisis específico
            if analysis_id:
                from bson import ObjectId
                triage_result = collection.find_one({
                    "_id": ObjectId(analysis_id),
                    "scan_type": "triage"
                })
                if not triage_result:
                    return {"error": "Análisis no encontrado"}
                triage_results = [triage_result]
            else:
                # Obtener el análisis más reciente
                triage_results = list(collection.find(
                    {"scan_type": "triage"}
                ).sort("timestamp", -1).limit(1))
            
            if not triage_results:
                return {"error": "No hay análisis de triage disponibles"}
            
            result = triage_results[0]
            result_data = result.get("result_data", {})
            
            detailed_analysis = {
                "analysis_info": {
                    "analysis_id": str(result.get("_id")),
                    "timestamp": result.get("timestamp"),
                    "metadata": result_data.get("analysis_metadata", {})
                },
                "vulnerability_correlation": {
                    "total_reported": result_data.get("vulnerabilities_reported", 0),
                    "total_confirmed": result_data.get("vulnerabilities_confirmed", 0),
                    "validation_summary": result_data.get("validation_summary", {})
                },
                "vulnerabilities_detailed": result_data.get("vulnerabilities_analysis", []),
                "executive_summary": result_data.get("executive_summary", {}),
                "recommendations": result_data.get("recommendations", {}),
                "metrics": result_data.get("metrics", {})
            }
            
            return detailed_analysis
            
        except Exception as e:
            self.logger.error(f"Error obteniendo análisis detallado: {e}")
            return {"error": str(e)}
    
    def get_statistics(self) -> Dict[str, Any]:
        """Obtiene estadísticas de los scans realizados"""
        
        if self.database is None:
            self.logger.error("No hay conexión activa a la base de datos")
            return {}
        
        try:
            collection = self.get_collection("scan_results")
            
            # Contar por tipo de scan
            pipeline = [
                {"$group": {
                    "_id": "$scan_type",
                    "count": {"$sum": 1},
                    "last_scan": {"$max": "$timestamp"}
                }}
            ]
            
            stats = list(collection.aggregate(pipeline))
            
            # Formatear estadísticas
            formatted_stats = {
                "total_scans": collection.count_documents({}),
                "by_type": {}
            }
            
            for stat in stats:
                formatted_stats["by_type"][stat["_id"]] = {
                    "count": stat["count"],
                    "last_scan": stat["last_scan"]
                }
            
            return formatted_stats
            
        except Exception as e:
            self.logger.error(f"Error obteniendo estadísticas: {e}")
            return {}