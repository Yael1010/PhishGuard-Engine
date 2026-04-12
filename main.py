import os
import sys

# Aseguramos que Python encuentre la carpeta src/
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from memory import MemoriaDeTrabajo
from engine import MotorInferencia

def simular_analisis():
    print("Iniciando PhishGuard - Simulación de Análisis Heurístico...\n")

    # 1. Creamos nuestro "correo simulado" (Hechos extraídos)
    correo_simulado = {
        "dominio_remitente": "soporte@miempresa.com",
        "dominio_ruta_retorno": "mailer@servidor-ruso.xyz", # Debería disparar H1 (+40 pts)
        "estado_SPF": "Aprobado",
        "estado_DKIM": "Aprobado",
        "lista_enlaces_URL": ["http://192.168.1.50/actualizacion"], # Debería disparar U1 (+45 pts)
        "texto_visible_enlace": "Actualizar cuenta",
        "destino_real_enlace": "http://192.168.1.50/actualizacion",
        "cuerpo_mensaje": "Estimado usuario, por favor inicie sesión para continuar.",
        "extension_adjunto": ".pdf"
    }

    print("Recepción de correo completada. Cargando datos...")

    # 2. Inicializamos los módulos del Sistema Basado en Conocimiento
    memoria = MemoriaDeTrabajo()
    motor = MotorInferencia(ruta_kb="config/knowledge_base.json")

    # 3. Cargamos los datos a la memoria de trabajo
    memoria.cargar_hechos(correo_simulado)

    # 4. Ejecutamos el motor (Forward Chaining)
    motor.ejecutar_forward_chaining(memoria)

    # 5. Obtenemos los resultados (Simulando el Módulo de Explicación)
    resultados = memoria.obtener_estado_actual()
    
    print("\n" + "="*60)
    print("RESULTADOS DEL ANÁLISIS DE PHISHGUARD")
    print("="*60)
    print(f"Clasificación Final : {memoria.clasificacion_final}")
    print(f"Puntaje de Riesgo   : {resultados['score_actual']} / 100")
    print("-" * 60)
    print("MÓDULO DE EXPLICACIÓN (Trazabilidad de reglas activadas):")
    
    if not resultados['reglas_disparadas']:
        print(" - No se detectaron anomalías.")
    else:
        for log in resultados['reglas_disparadas']:
            print(f" -> [Regla {log['regla']}] (+{log['peso_sumado']} pts) : {log['detalle']}")
    print("="*60 + "\n")

if __name__ == "__main__":
    simular_analisis()