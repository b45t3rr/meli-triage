#!/usr/bin/env python3
"""
Utilidades para interactuar con MongoDB desde línea de comandos
"""

import argparse
import json
import sys
import os
from datetime import datetime
from database.mongodb_client import MongoDBClient
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

def list_scans(client: MongoDBClient, scan_type: str = None, limit: int = 10):
    """Lista los scans realizados"""
    print(f"\n=== Listando scans (límite: {limit}) ===")
    
    results = client.get_scan_results(scan_type=scan_type, limit=limit)
    
    if not results:
        print("No se encontraron resultados")
        return
    
    for i, result in enumerate(results, 1):
        print(f"\n{i}. Scan ID: {result['_id']}")
        print(f"   Tipo: {result['scan_type']}")
        print(f"   Fecha: {result['timestamp']}")
        
        # Mostrar información específica según el tipo
        result_data = result.get('result_data', {})
        if result['scan_type'] == 'extraction':
            print(f"   PDF: {result_data.get('pdf_path', 'N/A')}")
            print(f"   Vulnerabilidades: {result_data.get('vulnerabilities_found', 0)}")
        elif result['scan_type'] == 'static_analysis':
            print(f"   Código: {result_data.get('source_code_path', 'N/A')}")
            print(f"   Hallazgos: {result_data.get('findings_count', 0)}")
        elif result['scan_type'] == 'dynamic_analysis':
            print(f"   URL: {result_data.get('target_url', 'N/A')}")
            print(f"   Vulnerabilidades: {result_data.get('vulnerabilities_found', 0)}")
        elif result['scan_type'] == 'triage':
            print(f"   Resultado consolidado disponible")

def show_statistics(client: MongoDBClient):
    """Muestra estadísticas de los scans"""
    print("\n=== Estadísticas de Scans ===")
    
    stats = client.get_statistics()
    
    if not stats:
        print("No se pudieron obtener estadísticas")
        return
    
    print(f"Total de scans: {stats.get('total_scans', 0)}")
    
    by_type = stats.get('by_type', {})
    if by_type:
        print("\nPor tipo de scan:")
        for scan_type, data in by_type.items():
            print(f"  {scan_type}: {data['count']} scans")
            print(f"    Último scan: {data['last_scan']}")

def show_scan_detail(client: MongoDBClient, scan_id: str):
    """Muestra el detalle de un scan específico"""
    print(f"\n=== Detalle del Scan {scan_id} ===")
    
    collection = client.get_collection("scan_results")
    if collection is None:
        print("Error: No se pudo acceder a la colección")
        return
    
    try:
        from bson import ObjectId
        result = collection.find_one({"_id": ObjectId(scan_id)})
        
        if not result:
            print(f"No se encontró el scan con ID: {scan_id}")
            return
        
        # Convertir ObjectId a string para mostrar
        result["_id"] = str(result["_id"])
        
        print(json.dumps(result, indent=2, default=str, ensure_ascii=False))
        
    except Exception as e:
        print(f"Error obteniendo detalle del scan: {e}")

def export_scans(client: MongoDBClient, output_file: str, scan_type: str = None):
    """Exporta scans a un archivo JSON"""
    print(f"\n=== Exportando scans a {output_file} ===")
    
    results = client.get_scan_results(scan_type=scan_type, limit=1000)
    
    if not results:
        print("No hay resultados para exportar")
        return
    
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump({
                "export_date": datetime.now().isoformat(),
                "total_scans": len(results),
                "scan_type_filter": scan_type,
                "scans": results
            }, f, indent=2, ensure_ascii=False, default=str)
        
        print(f"Exportados {len(results)} scans a {output_file}")
        
    except Exception as e:
        print(f"Error exportando scans: {e}")

def main():
    parser = argparse.ArgumentParser(description="Utilidades para MongoDB del sistema de vulnerabilidades")
    parser.add_argument("--host", default=os.getenv('MONGO_HOST', 'localhost'), help="Host de MongoDB")
    parser.add_argument("--port", type=int, default=int(os.getenv('MONGO_PORT', '27017')), help="Puerto de MongoDB")
    parser.add_argument("--username", default=os.getenv('MONGO_USERNAME', 'admin'), help="Usuario de MongoDB")
    parser.add_argument("--password", default=os.getenv('MONGO_PASSWORD', 'password123'), help="Contraseña de MongoDB")
    parser.add_argument("--database", default=os.getenv('MONGO_DATABASE', 'vulnerability_scanner'), help="Base de datos")
    
    subparsers = parser.add_subparsers(dest="command", help="Comandos disponibles")
    
    # Comando list
    list_parser = subparsers.add_parser("list", help="Listar scans")
    list_parser.add_argument("--type", help="Filtrar por tipo de scan")
    list_parser.add_argument("--limit", type=int, default=10, help="Límite de resultados")
    
    # Comando stats
    subparsers.add_parser("stats", help="Mostrar estadísticas")
    
    # Comando detail
    detail_parser = subparsers.add_parser("detail", help="Mostrar detalle de un scan")
    detail_parser.add_argument("scan_id", help="ID del scan")
    
    # Comando export
    export_parser = subparsers.add_parser("export", help="Exportar scans")
    export_parser.add_argument("output_file", help="Archivo de salida")
    export_parser.add_argument("--type", help="Filtrar por tipo de scan")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Conectar a MongoDB
    client = MongoDBClient(
        host=args.host,
        port=args.port,
        username=args.username,
        password=args.password,
        database_name=args.database
    )
    
    if not client.connect():
        print("Error: No se pudo conectar a MongoDB")
        sys.exit(1)
    
    try:
        if args.command == "list":
            list_scans(client, args.type, args.limit)
        elif args.command == "stats":
            show_statistics(client)
        elif args.command == "detail":
            show_scan_detail(client, args.scan_id)
        elif args.command == "export":
            export_scans(client, args.output_file, args.type)
    
    finally:
        client.disconnect()

if __name__ == "__main__":
    main()