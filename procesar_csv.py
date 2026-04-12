import os
import sys

# Aseguramos la ruta de las carpetas
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from extractor import ExtractorMasivo
from memory import MemoriaDeTrabajo
from engine import MotorInferencia

def analizar_lote(ruta_csv):
    print("="*60)
    print("🛡️ INICIANDO PHISHGUARD - ANÁLISIS MASIVO 🛡️")
    print("="*60)

    # 1. Inicializamos nuestros módulos
    extractor = ExtractorMasivo()
    motor = MotorInferencia(ruta_kb="config/knowledge_base.json")
    
    # 2. Cargamos el CSV
    df_correos = extractor.cargar_dataset(ruta_csv)
    
    if df_correos is None:
        return

    estadisticas = {"Legítimo": 0, "Sospechoso": 0, "Malicioso": 0}

    # 3. Iteramos fila por fila (correo por correo)
    for index, fila in df_correos.iterrows():
        id_correo = fila['id']
        
        # A) Extraemos hechos
        hechos = extractor.extraer_hechos_de_fila(fila)
        
        # B) Cargamos a memoria
        memoria = MemoriaDeTrabajo()
        memoria.cargar_hechos(hechos)
        
        # C) Ejecutamos inferencia
        motor.ejecutar_forward_chaining(memoria)
        
        # D) Guardamos el resultado
        clasificacion = memoria.clasificacion_final
        puntaje = memoria.puntaje_riesgo
        estadisticas[clasificacion] += 1
        
        # Imprimimos el log en consola
        if clasificacion == "Malicioso":
            color = "\033[91m" # Rojo
        elif clasificacion == "Sospechoso":
            color = "\033[93m" # Amarillo
        else:
            color = "\033[92m" # Verde
            
        reset_color = "\033[0m"
        print(f"[{id_correo}] Analizando correo de: {hechos['dominio_remitente']}")
        print(f" -> Resultado: {color}{clasificacion} ({puntaje}/100 pts){reset_color}")
        print("-" * 40)

    # 4. Resumen Final
    print("\n" + "="*60)
    print("📊 RESUMEN DEL ANÁLISIS 📊")
    print("="*60)
    print(f"Correos Legítimos : {estadisticas['Legítimo']}")
    print(f"Correos Sospechosos: {estadisticas['Sospechoso']}")
    print(f"Correos Maliciosos : {estadisticas['Malicioso']}")
    print("="*60)

if __name__ == "__main__":
    # Ruta a nuestro archivo de prueba
    ruta_archivo = "data/dataset_prueba.csv"
    analizar_lote(ruta_archivo)