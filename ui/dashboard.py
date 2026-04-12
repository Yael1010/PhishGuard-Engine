import os
import sys
import pandas as pd
from flask import Flask, render_template, request

directorio_base = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(os.path.join(directorio_base, 'src'))

from memory import MemoriaDeTrabajo
from engine import MotorInferencia
from extractor import ExtractorMasivo

app = Flask(__name__)

ruta_kb = os.path.join(directorio_base, 'config', 'knowledge_base.json')
motor = MotorInferencia(ruta_kb=ruta_kb)
extractor = ExtractorMasivo()

@app.route('/', methods=['GET', 'POST'])
def index():
    resultados_manual = None
    resultados_masivos = None
    estadisticas = None
    hechos_extraidos = None # Para mostrarle al usuario qué leyó el sistema del EML
    
    if request.method == 'POST':
        # CASO 1: Subida de CSV (Masivo)
        if 'archivo_csv' in request.files and request.files['archivo_csv'].filename != '':
            archivo = request.files['archivo_csv']
            try:
                df_correos = pd.read_csv(archivo)
                resultados_masivos = []
                estadisticas = {"Total": len(df_correos), "Legítimo": 0, "Sospechoso": 0, "Malicioso": 0}
                
                for _, fila in df_correos.iterrows():
                    hechos = extractor.extraer_hechos_de_fila(fila)
                    memoria = MemoriaDeTrabajo()
                    memoria.cargar_hechos(hechos)
                    motor.ejecutar_forward_chaining(memoria)
                    
                    clasificacion = memoria.clasificacion_final
                    estadisticas[clasificacion] += 1
                    
                    resultados_masivos.append({
                        'id': fila.get('id', 'N/A'),
                        'remitente': hechos['dominio_remitente'],
                        'asunto': fila.get('texto_enlace', 'Sin asunto'),
                        'clasificacion': clasificacion,
                        'score': memoria.puntaje_riesgo,
                        'reglas': [log['regla'] for log in memoria.reglas_activadas]
                    })
            except Exception as e:
                print(f"Error procesando CSV: {e}")

        # CASO 2: Subida de correo real .EML (Individual)
        elif 'archivo_eml' in request.files and request.files['archivo_eml'].filename != '':
            archivo = request.files['archivo_eml']
            hechos = extractor.extraer_hechos_de_eml(archivo)
            
            if hechos:
                hechos_extraidos = hechos
                memoria = MemoriaDeTrabajo()
                memoria.cargar_hechos(hechos)
                motor.ejecutar_forward_chaining(memoria)

                resultados_manual = memoria.obtener_estado_actual()
                resultados_manual['clasificacion'] = memoria.clasificacion_final

        # CASO 3: Formulario Manual (Escrito a mano)
        elif 'dominio_remitente' in request.form:
            correo_simulado = {
                "dominio_remitente": request.form.get('dominio_remitente', ''),
                "dominio_ruta_retorno": request.form.get('dominio_ruta_retorno', ''),
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

            resultados_manual = memoria.obtener_estado_actual()
            resultados_manual['clasificacion'] = memoria.clasificacion_final

    return render_template('index.html', 
                           resultados_manual=resultados_manual, 
                           resultados_masivos=resultados_masivos,
                           estadisticas=estadisticas,
                           hechos=hechos_extraidos)

if __name__ == '__main__':
    print("Iniciando Dashboard de PhishGuard en http://127.0.0.1:5000")
    app.run(debug=True, port=5000)