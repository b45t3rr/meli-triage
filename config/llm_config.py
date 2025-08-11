#!/usr/bin/env python3
"""
Configuración de modelos LLM para múltiples proveedores
Soporte para OpenAI, Anthropic, Google, DeepSeek, XAI, Groq, Mistral
"""

import os
from typing import Dict, Any, Optional
from langchain_openai import ChatOpenAI
from pydantic import SecretStr

# Mapeo de modelos disponibles por proveedor
MODEL_PROVIDERS = {
    "openai": {
        "models": [
            "gpt-5", "gpt-5-mini","gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-4", "gpt-3.5-turbo",
            "o1", "o1-mini", "o1-preview", "gpt-4o-2024-11-20", "gpt-4o-2024-08-06"
        ],
        "default": "gpt-4o-mini",
        "api_key_env": "OPENAI_API_KEY",
        "class_import": "langchain_openai.ChatOpenAI"
    },
    "anthropic": {
        "models": [
            "claude-3-5-sonnet-20241022", "claude-3-5-sonnet-20240620", 
            "claude-3-5-haiku-20241022", "claude-3-opus-20240229",
            "claude-3-sonnet-20240229", "claude-3-haiku-20240307",
            "claude-3-7-sonnet-20250219"
        ],
        "default": "claude-3-5-sonnet-20241022",
        "api_key_env": "ANTHROPIC_API_KEY",
        "class_import": "langchain_anthropic.ChatAnthropic"
    },
    "google": {
        "models": [
            "gemini-2.5-flash", "gemini-1.5-pro", "gemini-1.5-flash", 
            "gemini-1.0-pro", "gemini-2.0-flash-exp"
        ],
        "default": "gemini-2.5-flash",
        "api_key_env": "GOOGLE_API_KEY",
        "class_import": "langchain_google_genai.ChatGoogleGenerativeAI"
    },
    "deepseek": {
        "models": [
            "deepseek-chat", "deepseek-coder", "deepseek-reasoner"
        ],
        "default": "deepseek-chat",
        "api_key_env": "DEEPSEEK_API_KEY",
        "class_import": "langchain_deepseek.ChatDeepSeek"
    },
    "xai": {
        "models": [
            "grok-beta", "grok-3", "grok-3-mini", "grok-4-beta"
        ],
        "default": "grok-beta",
        "api_key_env": "XAI_API_KEY",
        "class_import": "langchain_xai.ChatXAI"
    },
    "groq": {
        "models": [
            "llama-3.3-70b-versatile", "llama-3.1-70b-versatile", 
            "llama-3.1-8b-instant", "mixtral-8x7b-32768", "gemma2-9b-it"
        ],
        "default": "llama-3.3-70b-versatile",
        "api_key_env": "GROQ_API_KEY",
        "class_import": "langchain_groq.ChatGroq"
    },
    "mistral": {
        "models": [
            "mistral-large-latest", "mistral-medium-latest", 
            "mistral-small-latest", "open-mistral-7b", "open-mixtral-8x7b"
        ],
        "default": "mistral-large-latest",
        "api_key_env": "MISTRAL_API_KEY",
        "class_import": "langchain_mistralai.ChatMistralAI"
    }
}

def get_available_models() -> Dict[str, Any]:
    """Retorna todos los modelos disponibles organizados por proveedor"""
    return MODEL_PROVIDERS

def parse_model_string(model_string: str) -> tuple[str, str]:
    """Parsea un string de modelo en formato 'proveedor:modelo' o solo 'modelo'"""
    if ":" in model_string:
        provider, model = model_string.split(":", 1)
        return provider.lower(), model
    else:
        # Intentar inferir el proveedor basado en el nombre del modelo
        model_lower = model_string.lower()
        
        # Patrones de inferencia
        if model_lower.startswith(("gpt-", "o1")):
            return "openai", model_string
        elif model_lower.startswith("claude-"):
            return "anthropic", model_string
        elif model_lower.startswith("gemini-"):
            return "google", model_string
        elif model_lower.startswith("deepseek-"):
            return "deepseek", model_string
        elif model_lower.startswith("grok-"):
            return "xai", model_string
        elif model_lower.startswith(("llama-", "mixtral-", "gemma")):
            return "groq", model_string
        elif model_lower.startswith(("mistral-", "open-mistral", "open-mixtral")):
            return "mistral", model_string
        else:
            # Por defecto, asumir OpenAI
            return "openai", model_string

def validate_model(provider: str, model: str) -> bool:
    """Valida si un modelo está disponible para un proveedor"""
    if provider not in MODEL_PROVIDERS:
        return False
    return model in MODEL_PROVIDERS[provider]["models"]

def create_llm_instance(model_string: str, temperature: float = 0.1, **kwargs) -> Any:
    """Crea una instancia del modelo LLM especificado"""
    provider, model = parse_model_string(model_string)
    
    if provider not in MODEL_PROVIDERS:
        raise ValueError(f"Proveedor no soportado: {provider}. Proveedores disponibles: {list(MODEL_PROVIDERS.keys())}")
    
    provider_config = MODEL_PROVIDERS[provider]
    
    # Verificar si el modelo está disponible
    if not validate_model(provider, model):
        available_models = provider_config["models"]
        raise ValueError(f"Modelo '{model}' no disponible para {provider}. Modelos disponibles: {available_models}")
    
    # Obtener API key
    api_key_env = provider_config["api_key_env"]
    api_key = os.getenv(api_key_env)
    
    if not api_key or api_key.startswith("your_"):
        raise ValueError(f"API key no configurada para {provider}. Configure la variable de entorno {api_key_env}")
    
    # Crear instancia según el proveedor
    try:
        if provider == "openai":
            from langchain_openai import ChatOpenAI
            return ChatOpenAI(
                model=model,
                api_key=api_key,
                temperature=temperature,
                **kwargs
            )
        
        elif provider == "anthropic":
            from langchain_anthropic import ChatAnthropic
            return ChatAnthropic(
                model=model,
                api_key=api_key,
                temperature=temperature,
                **kwargs
            )
        
        elif provider == "google":
            from langchain_google_genai import ChatGoogleGenerativeAI
            return ChatGoogleGenerativeAI(
                model=model,
                google_api_key=api_key,
                temperature=temperature,
                **kwargs
            )
        
        elif provider == "deepseek":
            # Use CrewAI's LLM class for better LiteLLM compatibility
            try:
                from crewai import LLM
                return LLM(
                    model=f"deepseek/{model}",
                    api_key=api_key,
                    temperature=temperature,
                    **kwargs
                )
            except ImportError:
                # Fallback to langchain_deepseek if CrewAI is not available
                from langchain_deepseek import ChatDeepSeek
                return ChatDeepSeek(
                    model=model,
                    temperature=temperature,
                    **kwargs
                )
        
        elif provider == "xai":
            # Use CrewAI's LLM class for better LiteLLM compatibility with xAI
            try:
                from crewai import LLM
                return LLM(
                    model=f"xai/{model}",
                    api_key=api_key,
                    temperature=temperature,
                    **kwargs
                )
            except ImportError:
                # Fallback to langchain_xai if CrewAI is not available
                from langchain_xai import ChatXAI
                return ChatXAI(
                    model=model,
                    api_key=api_key,
                    temperature=temperature,
                    **kwargs
                )
        
        elif provider == "groq":
            from langchain_groq import ChatGroq
            return ChatGroq(
                model=model,
                api_key=api_key,
                temperature=temperature,
                **kwargs
            )
        
        elif provider == "mistral":
            from langchain_mistralai import ChatMistralAI
            return ChatMistralAI(
                model=model,
                api_key=api_key,
                temperature=temperature,
                **kwargs
            )
        
        else:
            raise ValueError(f"Proveedor no implementado: {provider}")
    
    except ImportError as e:
        package_name = provider_config["class_import"].split(".")[0].replace("_", "-")
        raise ImportError(
            f"Paquete requerido no instalado para {provider}. "
            f"Instale con: pip install {package_name}"
        ) from e

def get_model_info(model_string: str) -> Dict[str, Any]:
    """Obtiene información sobre un modelo específico"""
    provider, model = parse_model_string(model_string)
    
    if provider not in MODEL_PROVIDERS:
        return {"error": f"Proveedor no soportado: {provider}"}
    
    provider_config = MODEL_PROVIDERS[provider]
    
    return {
        "provider": provider,
        "model": model,
        "is_valid": validate_model(provider, model),
        "available_models": provider_config["models"],
        "default_model": provider_config["default"],
        "api_key_env": provider_config["api_key_env"],
        "api_key_configured": bool(os.getenv(provider_config["api_key_env"]) and 
                                  not os.getenv(provider_config["api_key_env"], "").startswith("your_"))
    }

def list_available_models() -> str:
    """Retorna una lista formateada de todos los modelos disponibles"""
    output = ["\n🤖 Modelos LLM Disponibles:\n"]
    
    for provider, config in MODEL_PROVIDERS.items():
        api_key_env = config["api_key_env"]
        api_key = os.getenv(api_key_env, "")
        status = "✅" if api_key and not api_key.startswith("your_") else "❌"
        
        output.append(f"📦 {provider.upper()} {status}")
        output.append(f"   Modelo por defecto: {config['default']}")
        output.append(f"   Variable de entorno: {api_key_env}")
        output.append("   Modelos disponibles:")
        
        for model in config["models"]:
            prefix = "   • "
            if model == config["default"]:
                prefix = "   🌟 "
            output.append(f"{prefix}{model}")
        output.append("")
    
    output.append("💡 Uso: --model proveedor:modelo (ej: --model anthropic:claude-3-5-sonnet-20241022)")
    output.append("💡 O solo: --model modelo (se inferirá el proveedor)")
    
    return "\n".join(output)