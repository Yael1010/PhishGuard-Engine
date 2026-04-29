import os
import sys
import pandas as pd
from flask import Flask, render_template, request

# Configuración de rutas para encontrar los módulos en src/
directorio_base = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(os.path.join(directorio_base, 'src'))

from memory import MemoriaDeTrabajo
from engine import MotorInferencia
from extractor import ExtractorMasivo
from database import SupabaseManager # <--- Importamos la nueva integración

app = Flask(__name__)

# Inicializamos los módulos del sistema
ruta_kb = os.path.join(directorio_base, 'config', 'knowledge_base.json')
motor = MotorInferencia(ruta_kb=ruta_kb)
extractor = ExtractorMasivo()
db = SupabaseManager() # <--- Inicializamos el gestor de la nube

@app.route('/', methods=['GET', 'POST'])
def index():
    resultados_manual = None
    resultados_masivos = None
    hechos_extraidos = None
    
    if request.method == 'POST':
        # --- CASO 1: Análisis Automatizado (CSV) ---
        if 'archivo_csv' in request.files and request.files['archivo_csv'].filename != '':
            archivo = request.files['archivo_csv']
            try:
                df_correos = pd.read_csv(archivo)
                resultados_masivos = []
                
                for _, fila in df_correos.iterrows():
                    hechos = extractor.extraer_hechos_de_fila(fila)
                    memoria = MemoriaDeTrabajo()
                    memoria.cargar_hechos(hechos)
                    motor.ejecutar_forward_chaining(memoria)
                    
                    # Guardamos en Supabase cada registro del lote
                    db.guardar_registro(
                        remitente=hechos['dominio_remitente'],
                        score=memoria.puntaje_riesgo,
                        clasificacion=memoria.clasificacion_final,
                        tipo_amenaza=memoria.tipo_amenaza,
                        reglas=[log['regla'] for log in memoria.reglas_activadas]
                    )
                    
                    resultados_masivos.append({
                        'id': fila.get('id', 'N/A'),
                        'remitente': hechos['dominio_remitente'],
                        'clasificacion': memoria.clasificacion_final,
                        'tipo_amenaza': memoria.tipo_amenaza,
                        'score': memoria.puntaje_riesgo,
                        'reglas': [log['regla'] for log in memoria.reglas_activadas]
                    })
            except Exception as e:
                print(f"Error procesando CSV: {e}")

        # --- CASO 2: Escáner Individual (.EML) ---
        elif 'archivo_eml' in request.files and request.files['archivo_eml'].filename != '':
            archivo = request.files['archivo_eml']
            hechos = extractor.extraer_hechos_de_eml(archivo)
            
            if hechos:
                hechos_extraidos = hechos
                memoria = MemoriaDeTrabajo()
                memoria.cargar_hechos(hechos)
                motor.ejecutar_forward_chaining(memoria)

                # Guardamos el análisis del EML en la nube
                db.guardar_registro(
                    remitente=hechos['dominio_remitente'],
                    score=memoria.puntaje_riesgo,
                    clasificacion=memoria.clasificacion_final,
                    tipo_amenaza=memoria.tipo_amenaza,
                    reglas=[log['regla'] for log in memoria.reglas_activadas]
                )

                resultados_manual = memoria.obtener_estado_actual()
                resultados_manual['clasificacion'] = memoria.clasificacion_final
                resultados_manual['tipo_amenaza'] = memoria.tipo_amenaza

        # --- CASO 3: Simulación Manual ---
        elif 'dominio_remitente' in request.form:
            correo_simulado = {
                "dominio_remitente": request.form.get('dominio_remitente', '').lower(),
                "dominio_ruta_retorno": request.form.get('dominio_ruta_retorno', '').lower(),
                "estado_SPF": request.form.get('estado_SPF', 'Aprobado'),
                "estado_DKIM": request.form.get('estado_DKIM', 'Aprobado'),
                "lista_enlaces_URL": [request.form.get('destino_enlace', '')],
                "texto_visible_enlace": request.form.get('texto_enlace', ''),
                "destino_real_enlace": request.form.get('destino_enlace', ''),
                "cuerpo_mensaje": request.form.get('cuerpo_mensaje', ''),
                "extension_adjunto": request.form.get('extension_adjunto', '')
            }

            hechos_extraidos = correo_simulado
            memoria = MemoriaDeTrabajo()
            memoria.cargar_hechos(correo_simulado)
            motor.ejecutar_forward_chaining(memoria)

            # Guardamos la simulación manual en la nube
            db.guardar_registro(
                remitente=correo_simulado['dominio_remitente'],
                score=memoria.puntaje_riesgo,
                clasificacion=memoria.clasificacion_final,
                tipo_amenaza=memoria.tipo_amenaza,
                reglas=[log['regla'] for log in memoria.reglas_activadas]
            )

            resultados_manual = memoria.obtener_estado_actual()
            resultados_manual['clasificacion'] = memoria.clasificacion_final
            resultados_manual['tipo_amenaza'] = memoria.tipo_amenaza

    # --- DATOS PERSISTENTES PARA EL DASHBOARD ---
    # Recuperamos las estadísticas globales y el historial de la nube
    estadisticas_reales = db.obtener_resumen_estadistico()
    historial_db = db.obtener_historial_completo()

    return render_template('index.html', 
                           resultados_manual=resultados_manual, 
                           resultados_masivos=resultados_masivos,
                           estadisticas=estadisticas_reales, # <--- Estadísticas reales de Supabase
                           historial_db=historial_db,       # <--- Historial completo de Supabase
                           hechos=hechos_extraidos)

if __name__ == '__main__':
    # Iniciamos el servidor en el puerto 5000 con modo debug
    app.run(debug=True, port=5000)