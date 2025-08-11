#!/usr/bin/env python3
"""
Script para verificar la estructura de datos en MongoDB
"""

import sys
import os
import json
from datetime import datetime

# Agregar el directorio actual al path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from database.mongodb_client import MongoDBClient
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

def print_json_pretty(data, title=""):
    """Imprime JSON de manera legible"""
    if title:
        print(f"\n{'='*60}")
        print(f"{title}")
        print(f"{'='*60}")
    print(json.dumps(data, indent=2, ensure_ascii=False, default=str))

def main():
    """Función principal para verificar estructura de MongoDB"""
    
    print("🔍 VERIFICANDO ESTRUCTURA DE DATOS EN MONGODB")
    print("=" * 60)
    
    # Inicializar cliente MongoDB
    mongodb_client = MongoDBClient()
    
    # Conectar a MongoDB
    if not mongodb_client.connect():
        print("❌ Error: No se pudo conectar a MongoDB")
        print("Asegúrate de que MongoDB esté ejecutándose y las credenciales sean correctas")
        return
    
    print("✅ Conectado a MongoDB exitosamente")
    
    try:
        # Obtener todos los resultados de scan
        print("\n📊 OBTENIENDO RESULTADOS DE SCAN...")
        all_results = mongodb_client.get_scan_results(limit=5)
        
        if all_results:
            print(f"\n📄 ENCONTRADOS {len(all_results)} RESULTADOS:")
            
            for i, result in enumerate(all_results):
                print(f"\n--- RESULTADO {i+1} ---")
                print(f"ID: {result.get('_id', 'N/A')}")
                print(f"Tipo de Scan: {result.get('scan_type', 'N/A')}")
                print(f"Timestamp: {result.get('timestamp', 'N/A')}")
                
                # Mostrar estructura del result_data
                result_data = result.get('result_data', {})
                print(f"\n📋 ESTRUCTURA DE result_data:")
                
                if isinstance(result_data, dict):
                    print(f"   Tipo: Diccionario con {len(result_data)} campos")
                    print(f"   Campos principales: {list(result_data.keys())}")
                    
                    # Mostrar algunos campos específicos
                    if 'pdf_path' in result_data:
                        print(f"   PDF Path: {os.path.basename(result_data['pdf_path'])}")
                    
                    if 'vulnerabilities_reported' in result_data:
                        print(f"   Vulnerabilidades Reportadas: {result_data['vulnerabilities_reported']}")
                    
                    if 'vulnerabilities' in result_data:
                        vulns = result_data['vulnerabilities']
                        if isinstance(vulns, list):
                            print(f"   Lista de Vulnerabilidades: {len(vulns)} elementos")
                        else:
                            print(f"   Vulnerabilidades (tipo {type(vulns).__name__}): {str(vulns)[:100]}...")
                    
                    if 'extraction_summary' in result_data:
                        summary = result_data['extraction_summary']
                        print(f"   Resumen de Extracción: {summary}")
                    
                elif isinstance(result_data, str):
                    print(f"   Tipo: String (longitud: {len(result_data)})")
                    print(f"   Contenido (primeros 200 chars): {result_data[:200]}...")
                    
                    # Intentar parsear como JSON
                    try:
                        parsed = json.loads(result_data)
                        print(f"   ✅ Es JSON válido con {len(parsed)} campos: {list(parsed.keys()) if isinstance(parsed, dict) else 'No es diccionario'}")
                    except:
                        print(f"   ❌ No es JSON válido")
                
                else:
                    print(f"   Tipo: {type(result_data).__name__}")
                    print(f"   Valor: {str(result_data)[:200]}...")
                
                # Mostrar metadata si existe
                metadata = result.get('metadata', {})
                if metadata:
                    print(f"\n📝 METADATA: {metadata}")
                
                print("-" * 60)
            
            # Mostrar un ejemplo completo del primer resultado
            if all_results:
                print_json_pretty(all_results[0], "EJEMPLO COMPLETO DEL PRIMER RESULTADO")
        
        else:
            print("⚠️  No se encontraron resultados en la base de datos")
            print("\n💡 Para generar datos de prueba, ejecuta:")
            print("   python main.py /ruta/al/archivo.pdf")
    
    except Exception as e:
        print(f"❌ Error durante la consulta: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        # Cerrar conexión
        mongodb_client.disconnect()
        print("\n✅ Conexión a MongoDB cerrada")

if __name__ == "__main__":
    main()