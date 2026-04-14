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
        enlaces = hechos.get("lista_enlaces_URL", [])
        
        # Regla U1: URL con Dirección IP
        patron_ip = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        if any(patron_ip.search(enlace) for enlace in enlaces):
            self._disparar_regla("U1", memoria)

        # Regla U2: Discrepancia de Enlace Visible
        texto_visible = str(hechos.get("texto_visible_enlace", "")).lower().strip()
        destino_real = str(hechos.get("destino_real_enlace", "")).lower().strip()
        parece_url = re.search(r'\.[a-z]{2,4}(/|$)', texto_visible) or "http" in texto_visible
        
        if parece_url and texto_visible != destino_real:
            self._disparar_regla("U2", memoria)

        # Regla U3: Uso de Acortadores 
        acortadores_conocidos = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"]
        if any(acortador in enlace.lower() for enlace in enlaces for acortador in acortadores_conocidos):
            self._disparar_regla("U3", memoria)

        # --- GRUPO 3: Análisis Semántico ---
        cuerpo = hechos.get("cuerpo_mensaje", "").lower()
        
        # Regla S1: Sentido de Urgencia o Amenaza
        palabras_urgencia = ["acción requerida", "cuenta suspendida", "urgente", "verificar cuenta", "bloqueada"]
        if any(palabra in cuerpo for palabra in palabras_urgencia):
            self._disparar_regla("S1", memoria)

        # Regla S2: Falta de Personalización (Saludos genéricos)
        saludos_genericos = ["estimado cliente", "estimado usuario", "querido usuario", "dear customer"]
        if any(saludo in cuerpo for saludo in saludos_genericos):
            self._disparar_regla("S2", memoria)

        # --- GRUPO 4: Archivos Adjuntos ---
        ext_adjunto = hechos.get("extension_adjunto", "").lower()
        
        # Regla A1: Extensiones Peligrosas
        extensiones_malas = [".exe", ".bat", ".vbs", ".ps1", ".scr"]
        if ext_adjunto in extensiones_malas:
            self._disparar_regla("A1", memoria)

        # Regla A2: Archivos Comprimidos/Cifrados
        extensiones_comprimidas = [".zip", ".rar", ".7z"]
        if ext_adjunto in extensiones_comprimidas:
            self._disparar_regla("A2", memoria)

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
        
        # Topes Heurísticos: Normalización a 100 máximo
        if memoria.puntaje_riesgo > 100:
            memoria.puntaje_riesgo = 100

        score = memoria.puntaje_riesgo
        
        # LÓGICA DE DEDUCCIÓN (Spam vs Phishing)
        # Consideramos que las reglas de ofuscación de URLs (U), manipulación (S1) 
        # y payloads (A) son claros indicadores de un ataque de Phishing/Malware.
        reglas_phishing = ["U1", "U2", "U3", "S1", "A1", "A2"]
        ids_activados = [log["regla"] for log in memoria.reglas_activadas]
        tiene_phishing = any(r in ids_activados for r in reglas_phishing)

        # Clasificación Final basada en el JSON
        if score >= self.umbrales["malicioso_min"]: # Mayor o igual a 71
            memoria.clasificacion_final = "Malicioso"
            memoria.tipo_amenaza = "Phishing" if tiene_phishing else "Spam Severo"
            
        elif score >= self.umbrales["sospechoso_min"]: # Mayor o igual a 31
            memoria.clasificacion_final = "Sospechoso"
            memoria.tipo_amenaza = "Phishing" if tiene_phishing else "Spam"
            
        else: # Menor a 31
            memoria.clasificacion_final = "Legítimo"
            memoria.tipo_amenaza = "Ninguna"