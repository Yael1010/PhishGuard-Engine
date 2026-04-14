import json
import re

class MotorInferencia:
    def __init__(self, ruta_kb="config/knowledge_base.json"):
        """
        Al iniciar el motor, cargamos la Base de Conocimiento (el archivo JSON).
        Esto separa la lógica del código de los pesos matemáticos.
        """
        with open(ruta_kb, 'r', encoding='utf-8') as archivo:
            self.kb = json.load(archivo)
        
        # Convertimos la lista de reglas en un diccionario para acceder rápido a ellas por su ID
        self.reglas = {regla["id_regla"]: regla for regla in self.kb["reglas"]}
        self.umbrales = self.kb["umbrales_decision"]

    def ejecutar_forward_chaining(self, memoria):
        """
        Dirigido por datos: Toma los hechos iniciales de la memoria y 
        evalúa qué reglas se cumplen para sumar el puntaje de riesgo.
        """
        hechos = memoria.hechos_iniciales

        # --- GRUPO 1: Metadatos y Cabeceras ---
        # Regla H1: Inconsistencia de Dominio
        if hechos.get("dominio_remitente") != hechos.get("dominio_ruta_retorno"):
            self._disparar_regla("H1", memoria)

        # Regla H2: Fallo de Autenticación
        if hechos.get("estado_SPF") == "Fallo" or hechos.get("estado_DKIM") == "Fallo":
            self._disparar_regla("H2", memoria)

        # --- GRUPO 2: Análisis de Enlaces ---
        # Regla U1: URL con Dirección IP (Usamos una expresión regular básica para IPv4)
        patron_ip = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        enlaces = hechos.get("lista_enlaces_URL", [])
        if any(patron_ip.search(enlace) for enlace in enlaces):
            self._disparar_regla("U1", memoria)

        # Regla U2: Discrepancia de Enlace Visible
        # Solo se activa si el texto visible PARECE una URL (contiene .com, .mx, http) 
        # pero redirige a un lugar totalmente distinto.
        texto_visible = str(hechos.get("texto_visible_enlace", "")).lower().strip()
        destino_real = str(hechos.get("destino_real_enlace", "")).lower().strip()
        
        # Verificamos si el texto visible intenta aparentar ser un link
        parece_url = re.search(r'\.[a-z]{2,4}(/|$)', texto_visible) or "http" in texto_visible
        
        if parece_url and texto_visible != destino_real:
            self._disparar_regla("U2", memoria)

        # --- GRUPO 3: Análisis Semántico ---
        # Regla S1: Sentido de Urgencia
        cuerpo = hechos.get("cuerpo_mensaje", "").lower()
        palabras_urgencia = ["acción requerida", "cuenta suspendida", "urgente", "verificar cuenta"]
        if any(palabra in cuerpo for palabra in palabras_urgencia):
            self._disparar_regla("S1", memoria)

        # --- GRUPO 4: Archivos Adjuntos ---
        # Regla A1: Extensiones Peligrosas
        extensiones_malas = [".exe", ".bat", ".vbs", ".ps1", ".scr"]
        ext_adjunto = hechos.get("extension_adjunto", "").lower()
        if ext_adjunto in extensiones_malas:
            self._disparar_regla("A1", memoria)

        # --- EVALUACIÓN FINAL ---
        self._clasificar_riesgo(memoria)

    def _disparar_regla(self, id_regla, memoria):
        """Función auxiliar para registrar el peso y el log en la memoria."""
        regla = self.reglas[id_regla]
        memoria.registrar_activacion(
            id_regla=regla["id_regla"], 
            peso=regla["peso_asignado"], 
            descripcion=regla["descripcion"]
        )

    def _clasificar_riesgo(self, memoria):
        """Aplica los umbrales de decisión y deduce el tipo de amenaza."""
        if memoria.puntaje_riesgo > 100:
            memoria.puntaje_riesgo = 100

        score = memoria.puntaje_riesgo
        
        # LÓGICA DE DEDUCCIÓN (Spam vs Phishing)
        # Si se activó alguna de estas reglas, hay intención de engaño o malware
        reglas_phishing = ["U1", "U2", "S1", "A1"]
        ids_activados = [log["regla"] for log in memoria.reglas_activadas]
        tiene_phishing = any(r in ids_activados for r in reglas_phishing)

        # Clasificación Final
        if score >= self.umbrales["malicioso_min"]: # >= 71
            memoria.clasificacion_final = "Malicioso"
            memoria.tipo_amenaza = "Phishing" if tiene_phishing else "Spam Severo"
            
        elif score >= self.umbrales["sospechoso_min"]: # >= 31
            memoria.clasificacion_final = "Sospechoso"
            memoria.tipo_amenaza = "Phishing" if tiene_phishing else "Spam"
            
        else: # < 31
            memoria.clasificacion_final = "Legítimo"
            memoria.tipo_amenaza = "Ninguna"